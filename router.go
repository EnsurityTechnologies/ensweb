package ensweb

import (
	"github.com/gorilla/mux"
)

// func (s *Server) SetIndex(dirPath string) {
// 	s.mux.Handle("/", s.IndexRoute(dirPath)).Methods("GET")
// }

func (s *Server) AddRoute(path string, method string, hf HandlerFunc) {
	s.mux.Handle(path, basicHandleFunc(s, hf)).Methods(method)
	s.mux.Handle(path, basicPreflightHandleFunc(s)).Methods("OPTIONS")
}

func (s *Server) AddPrefixRoute(prefix string, hf HandlerFunc) {
	s.mux.PathPrefix(prefix).Handler(basicHandleFunc(s, hf))
}

func (s *Server) GetMux() *mux.Router {
	return s.mux
}

// func (s *Server) EnableSWagger(url string) {

// 	s.mux.PathPrefix("/swagger/").Handler(httpSwagger.Handler(
// 		httpSwagger.URL(url+"/swagger/doc.json"),
// 		httpSwagger.DeepLinking(true),
// 		httpSwagger.DocExpansion("none"),
// 		httpSwagger.DomID("swagger-ui"))).Methods(http.MethodGet)
// }

// func (s *Server) SetStatic(dir string) {
// 	s.rootDir = dir
// 	s.mux.PathPrefix("/").Handler(http.FileServer(http.Dir(dir)))
// }

func (s *Server) SetStatic(prefix string, dir string) {
	s.rootDir = dir
	s.prefixPath = prefix
	s.mux.PathPrefix("/").Handler(indexRoute(s, dir))
}

func (s *Server) GetRouteVar(req *Request, key string) string {
	vars := mux.Vars(req.r)
	return vars[key]
}
