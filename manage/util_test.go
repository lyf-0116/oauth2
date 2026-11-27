package manage_test

import (
	"testing"

	"github.com/go-oauth2/oauth2/v4/errors"
	"github.com/go-oauth2/oauth2/v4/manage"

	. "github.com/smartystreets/goconvey/convey"
)

func TestUtil(t *testing.T) {
	Convey("Util Test", t, func() {
		Convey("ValidateURI Test", func() {
			err := manage.DefaultValidateURI("http://www.example.com", "http://www.example.com/cb?code=xxx")
			So(err, ShouldBeNil)
		})

		Convey("ValidateURI uses normalized exact hosts", func() {
			So(manage.DefaultValidateURI("https://example.com", "https://EVILexample.com/cb"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://example.com", "https://example.com.evil.com/cb"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://EXAMPLE.com.", "https://example.com/cb"),
				ShouldBeNil)
		})

		Convey("ValidateURI compares port, path and query", func() {
			So(manage.DefaultValidateURI("https://example.com:8443/cb", "https://example.com:9443/cb"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://example.com/cb", "https://example.com/other"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://example.com/", "https://example.com/other"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://example.com/cb?a=1", "https://example.com/cb?a=2"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://example.com/cb?a=1", "https://example.com/cb?a=1"),
				ShouldBeNil)
		})

		Convey("ValidateURI normalizes paths before matching", func() {
			So(manage.DefaultValidateURI("https://example.com/cb", "https://example.com/cb/../admin"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://example.com/cb", "https://example.com/cb//../admin"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.DefaultValidateURI("https://example.com/cb", "https://example.com/cb/./"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
		})

		Convey("StrictValidateURI disables legacy domain-only compatibility", func() {
			So(manage.StrictValidateURI("https://example.com", "https://example.com/cb"),
				ShouldBeError, errors.ErrInvalidRedirectURI)
			So(manage.StrictValidateURI("https://example.com/cb", "https://example.com/cb"),
				ShouldBeNil)
		})
	})
}
