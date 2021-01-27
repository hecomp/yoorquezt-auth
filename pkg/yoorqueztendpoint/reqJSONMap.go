package yoorqueztendpoint

// SignupResponse collects the response values for the Signup method.
type SignupResponse struct {
	Status  bool        `json:"status"`
	Message   string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err       error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// SignupResponse collects the response values for the Signup method.
type LoginResponse struct {
	Status  bool        `json:"status"`
	Message string   `json:",omitempty"`
	Data    interface{} `json:"data"`
	Err     error `json:"err,omitempty"` // should be intercepted by Failed/errorEncoder
}

// GenericResponse is the format of our response
type GenericResponse struct {
	Status  bool        `json:"status"`
	Message string      `json:"message"`
	Data    interface{} `json:"data"`
	Err       error `json:"err,omitempty"`
}

// ValidationError is a collection of validation error messages
type ValidationError struct {
	Errors []string `json:"errors"`
}

// Below data types are used for encoding and decoding b/t go types and json
type TokenResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
}

type AuthResponse struct {
	RefreshToken string `json:"refresh_token"`
	AccessToken  string `json:"access_token"`
	Username     string `json:"username"`
}

type UsernameUpdate struct {
	Username string `json:"username"`
}

type CodeVerificationReq struct {
	Code string `json: "code"`
	Type string `json" "type"`
}

type PasswordResetReq struct {
	Password string `json: "password"`
	PasswordRe string `json: "password_re"`
	Code 		string `json: "code"`
}
