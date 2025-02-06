package handlers

import (
	"fmt"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/LMBishop/gunnel/pkg/store"
)

func ReverseProxy(storeService store.Service) func(http.ResponseWriter, *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		hostParts := strings.Split(r.Host, ".")

		slug := hostParts[0]
		rule := storeService.GetRuleBySlug(slug)
		if rule == nil {
			http.Error(w, fmt.Sprintf("Unknown peer '%s'", slug), http.StatusNotFound)
			return
		}

		targetURL, err := url.Parse("http://" + rule.Peer.IPAddr.String() + ":" + rule.Port)
		rule.LastUsed = time.Now()
		if err != nil {
			http.Error(w, "Invalid target URL", http.StatusInternalServerError)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(targetURL)
		proxy.ServeHTTP(w, r)
	}
}
