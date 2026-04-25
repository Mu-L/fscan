//go:build !web

package api

import (
	"net/http"

	"github.com/shadow1ng/fscan/web/ws"
)

// RegisterRoutes 非Web版本的空实现
func RegisterRoutes(mux *http.ServeMux, hub *ws.Hub) {
	// 非Web版本不注册任何路由
}
