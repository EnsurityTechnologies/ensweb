package ensweb

import (
	"bytes"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

func (s *Server) enableCors(w *http.ResponseWriter) {
	(*w).Header().Set("Access-Control-Allow-Origin", "*")
	(*w).Header().Set("Access-Control-Allow-Methods", "GET,POST,PUT,DELETE,OPTIONS")
	(*w).Header().Set("Access-Control-Allow-Headers", s.allowHeaders)
}

func (s *Server) addDefaultHeaders(w *http.ResponseWriter) {
	for k, v := range s.defaultHeaders {
		(*w).Header().Set(k, v)
	}
}

func (s *Server) SetHeaders(req *Request, headers map[string]string) {
	if req.w != nil {
		for k, v := range headers {
			req.w.Header().Set(k, v)
		}
	}
}

func (s *Server) RenderJSON(req *Request, model interface{}, status int) *Result {
	if s.debugMode {
		s.enableCors(&req.w)
	}
	s.addDefaultHeaders(&req.w)
	req.w.Header().Set("Content-Type", "application/json")

	res := &Result{
		Status: status,
		Done:   true,
	}

	if model == nil {
		res.Status = http.StatusNoContent
		req.w.WriteHeader(http.StatusNoContent)
	} else {
		enc := json.NewEncoder(req.w)
		if s.secureAPI {
			err := s.getSharedSecret(req)
			if err != nil {
				req.w.WriteHeader(http.StatusInternalServerError)
				res.Status = http.StatusInternalServerError
				return res
			}
			data, err := encryptModel(req.nss, req.ss, model)
			if err != nil {
				s.log.Error("failed to encrypt output model", "err", err)
			}
			sd := SecureData{
				Data: data,
			}
			req.w.WriteHeader(status)
			enc.Encode(sd)
		} else {
			req.w.WriteHeader(status)
			enc.Encode(model)
		}
	}
	return res
}

func (s *Server) RenderNormalJSON(req *Request, model interface{}, status int) *Result {
	if s.debugMode {
		s.enableCors(&req.w)
	}
	s.addDefaultHeaders(&req.w)
	req.w.Header().Set("Content-Type", "application/json")
	res := &Result{
		Status: status,
		Done:   true,
	}
	if model == nil {
		res.Status = http.StatusNoContent
		req.w.WriteHeader(http.StatusNoContent)
	} else {
		enc := json.NewEncoder(req.w)
		req.w.WriteHeader(status)
		enc.Encode(model)
	}
	return res
}

func (s *Server) RenderJSONErrorResponse(req *Request, status int, errMsg string, log bool, args ...interface{}) *Result {
	if log {
		s.log.Error(errMsg, args...)
	}
	model := BaseResponse{
		Message: ToTitleCase(errMsg),
	}
	return s.RenderJSON(req, model, status)
}

func (s *Server) RenderJSONError(req *Request, status int, errMsg string, logMsg string, args ...interface{}) *Result {
	if logMsg != "" {
		s.log.Error(logMsg, args...)
	}
	model := BaseResponse{
		Message: ToTitleCase(errMsg),
	}
	return s.RenderJSON(req, model, status)
}

func (s *Server) RenderJSONSuccessResponse(req *Request, msg string, log bool, args ...interface{}) *Result {
	if log {
		s.log.Info(msg, args...)
	}
	model := BaseResponse{
		Status:  true,
		Message: ToTitleCase(msg),
	}
	return s.RenderJSON(req, model, http.StatusOK)
}

func (s *Server) RenderJSONStatus(req *Request, status string, message string, logMsg string, args ...interface{}) *Result {
	if logMsg != "" {
		s.log.Error(logMsg, args...)
	}
	model := StatusMsg{
		Status:  status,
		Message: message,
	}
	return s.RenderJSON(req, model, http.StatusOK)
}

func (s *Server) RenderTemplate(req *Request, renderPath string, model interface{}, status int) *Result {
	templateFile := s.rootDir + renderPath + ".html"
	s.log.Debug("Template filename : " + templateFile)
	t, err := template.ParseFiles(templateFile)
	if err != nil {
		return s.RenderJSON(req, nil, http.StatusNotFound)
	}
	s.addDefaultHeaders(&req.w)
	err = t.Execute(req.w, model)
	if err != nil {
		fmt.Printf("Error : %s\n", err.Error())
		return s.RenderJSON(req, nil, http.StatusInternalServerError)
	}
	res := &Result{
		Status: status,
		Done:   true,
	}
	return res
}

func (s *Server) RenderFile(req *Request, fileName string, attachment bool) *Result {

	if s.debugMode {
		s.enableCors(&req.w)
	}

	res := &Result{
		Status: http.StatusOK,
		Done:   true,
	}
	s.addDefaultHeaders(&req.w)
	if attachment {
		f, err := os.Open(fileName)
		defer f.Close() //Close after function return
		if err != nil {
			//File not found, send 404
			http.Error(req.w, "File not found.", 404)
			res.Status = http.StatusNotFound
			return res
		}

		//File is found, create and send the correct headers

		//Get the Content-Type of the file
		//Create a buffer to store the header of the file in
		FileHeader := make([]byte, 512)
		//Copy the headers into the FileHeader buffer
		f.Read(FileHeader)
		//Get content type of file
		FileContentType := http.DetectContentType(FileHeader)

		//Get the file size
		FileStat, _ := f.Stat()                            //Get info from file
		FileSize := strconv.FormatInt(FileStat.Size(), 10) //Get file size as a string

		//Send the headers
		req.w.Header().Set("Content-Disposition", "attachment; filename="+fileName)
		req.w.Header().Set("Content-Type", FileContentType)
		req.w.Header().Set("Content-Length", FileSize)

		//Send the file
		//We read 512 bytes from the file already, so we reset the offset back to 0
		f.Seek(0, 0)
		io.Copy(req.w, f) //'Copy' the file to the client
	} else {
		http.ServeFile(req.w, req.r, fileName)
	}

	return res
}

func (s *Server) RenderMultiFormFile(req *Request, field map[string]string, fileName map[string]string) *Result {

	if s.debugMode {
		s.enableCors(&req.w)
	}
	s.addDefaultHeaders(&req.w)

	res := &Result{
		Status: http.StatusOK,
		Done:   true,
	}

	body := new(bytes.Buffer)

	writer := multipart.NewWriter(body)

	for k, v := range field {
		wr, _ := writer.CreateFormField(k)
		wr.Write([]byte(v))
	}

	for k, v := range fileName {

		f, err := os.Open(v)
		if err != nil {
			return s.RenderJSON(req, nil, http.StatusInternalServerError)
		}
		part, err := writer.CreateFormFile(k, filepath.Base(v))
		if err != nil {
			f.Close()
			return s.RenderJSON(req, nil, http.StatusInternalServerError)
		}
		_, err = io.Copy(part, f)
		if err != nil {
			f.Close()
			return s.RenderJSON(req, nil, http.StatusInternalServerError)
		}
		f.Close()
	}
	err := writer.Close()
	if err != nil {
		return s.RenderJSON(req, nil, http.StatusInternalServerError)
	}
	req.w.Header().Set("Content-Type", writer.FormDataContentType())
	req.w.WriteHeader(http.StatusOK)
	// wrData, err := ioutil.ReadAll(body)
	// if err != nil {
	// 	return s.RenderJSON(req, nil, http.StatusInternalServerError)
	// }
	req.w.Write(body.Bytes())
	return res
}

func (s *Server) RenderImage(req *Request, contentType string, img string) *Result {

	if s.debugMode {
		s.enableCors(&req.w)
	}
	s.addDefaultHeaders(&req.w)
	req.w.Header().Set("Content-Type", contentType)

	res := &Result{
		Status: http.StatusOK,
		Done:   true,
	}
	req.w.WriteHeader(http.StatusOK)

	str := "data:" + contentType + ";base64," + img
	f, _ := os.Create("test.txt")
	f.WriteString(str)
	f.Close()

	fmt.Printf("Length : %d\n", len(str))
	req.w.Write([]byte(str))
	return res
}
