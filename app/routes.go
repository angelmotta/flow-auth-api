package app

// routes defines all routes for the AuthServer
func (a *AuthServer) routes() {
	a.Router.Post("/api/auth/login/google", a.handleLoginGoogle)
	a.Router.Post("/api/auth/login/token", a.handleAuthorization)
	a.Router.Post("/api/auth/signup", a.handleSignup)
	a.Router.Post("/api/auth/signup/user", a.handleSignupUser)
}
