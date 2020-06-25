package gopaque_test

import (
	"bytes"
	"fmt"

	"github.com/ivn-nz/gopaque/gopaque"
)

// This simple example doesn't marshal the messages, it just sends them.
func Example_simple() {
	crypto := gopaque.CryptoDefault
	// Registration first...create user side and server side
	userReg := gopaque.NewUserRegister(crypto, []byte("user foo"), nil)
	serverReg := gopaque.NewServerRegister(crypto, crypto.NewKey(nil))
	// Do the registration steps
	userRegInit := userReg.Init([]byte("test"))
	serverRegInit := serverReg.Init(userRegInit)
	userRegComplete := userReg.Complete(serverRegInit)
	serverRegComplete := serverReg.Complete(userRegComplete)
	// XXX: Here is where serverRegComplete would be persisted on the server.

	// Now that we are registered, do an auth. We are using an embedded key
	// exchange here instead of having our own externally which means we have
	// one extra "Finish" step. Note, in other cases we might hold on to the
	// created key exchange so we can get things like the shared secret.
	userAuth := gopaque.NewUserAuth(crypto, []byte("user foo"), gopaque.NewKeyExchangeSigma(crypto))
	serverAuth := gopaque.NewServerAuth(crypto, gopaque.NewKeyExchangeSigma(crypto))
	// Do the auth
	userAuthInit, err := userAuth.Init([]byte("test"))
	panicIfErr(err)
	// XXX: Here is where serverRegComplete would be looked up by userAuthInit.UserID.
	serverAuthComplete, err := serverAuth.Complete(userAuthInit, serverRegComplete)
	panicIfErr(err)
	userAuthFinish, userAuthComplete, err := userAuth.Complete(serverAuthComplete)
	//userAuthFinishExt, _, err := userAuth.CompleteExt(serverAuthComplete)
	panicIfErr(err)
	err = serverAuth.Finish(userAuthComplete)
	panicIfErr(err)
	a, _ := userReg.PrivateKey().MarshalBinary()
	b, _ := userAuthFinish.UserPrivateKey.MarshalBinary()
	// Might as well check that the user key is the same as orig
	if bytes.Compare(a, b) == 0 { // Equal
		fmt.Println("Key ok")
	} else {
		panic("Key mismatch")
	}

	// Output: Key ok
}
