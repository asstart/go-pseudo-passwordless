package auth

import (
	"github.com/asstart/go-session"
	"github.com/asstart/go-pseudo-passwordless/auth/token"
	"github.com/go-playground/locales/en"
	ut "github.com/go-playground/universal-translator"
	"github.com/go-playground/validator/v10"
)

const (
	CstmSessionValidatorKey = "custom_session_format"
	CstmTokenValidatorKey   = "custom_token_format"
	DfltEmailKey            = "email"
	DfltRequiredKey         = "required"
)

type validatorCfg struct {
	f       func(fl validator.FieldLevel) bool
	message string
}

var validators = map[string]validatorCfg{
	CstmSessionValidatorKey: {SessionValidator(), "invalid session id"},
	CstmTokenValidatorKey:   {TokenValidator(), "invalid token id"},
	DfltEmailKey:            {nil, "should be email"},
	DfltRequiredKey:         {nil, "{0} is required"},
}

func SessionValidator() func(fl validator.FieldLevel) bool {
	return func(fl validator.FieldLevel) bool {
		err := session.ValidateSessionID(fl.Field().String())
		return err == nil
	}
}

func TokenValidator() func(fl validator.FieldLevel) bool {
	return func(fl validator.FieldLevel) bool {
		err := token.Validate(fl.Field().String())
		return err == nil
	}
}

func RegistrateCustomVldtrs() (*validator.Validate, ut.Translator, error) {
	return registrateValidators(validators)
}

func RegistrateVldtrs(validatorsList map[string]validatorCfg) (*validator.Validate, ut.Translator, error) {
	return registrateValidators(validatorsList)
}

func registrateValidators(validatorsList map[string]validatorCfg) (*validator.Validate, ut.Translator, error) {
	vld := validator.New()

	en := en.New()
	uni := ut.New(en, en)

	tr, _ := uni.GetTranslator("en")

	for k, v := range validators {
		if v.f != nil {
			err := vld.RegisterValidation(k, v.f)
			if err != nil {
				return nil, nil, err
			}
		}
		if v.message != "" {
			err := registrateCustromTrnsltrs(vld, tr, k, v.message)
			if err != nil {
				return nil, nil, err
			}
		}
	}

	return vld, tr, nil
}

func registrateCustromTrnsltrs(vld *validator.Validate, tr ut.Translator, key, msg string) error {
	err := vld.RegisterTranslation(key, tr,
		func(tr ut.Translator) error {
			return tr.Add(key, msg, true)
		}, func(ut ut.Translator, fe validator.FieldError) string {
			t, _ := ut.T(key, fe.Field())
			return t
		},
	)
	return err
}
