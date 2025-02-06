package handlers

import (
	"net/http"

	"github.com/LMBishop/gunnel/pkg/config"
	"github.com/LMBishop/gunnel/web"
)

func Index(configService config.Service) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		web.Index().Execute(w, struct {
			Host        string
			ExpireAfter int
			Iface       string
		}{
			Host:        configService.Config().Hostname,
			ExpireAfter: configService.Config().ExpireAfter,
			Iface:       configService.Config().WireGuard.InterfaceName,
		})
	}
}
