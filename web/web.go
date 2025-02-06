package web

import (
	"embed"
	"html/template"
)

//go:embed *
var files embed.FS

func Index() *template.Template {
	return template.Must(template.ParseFS(files, "index.html"))
}
