/* SPDX-License-Identifier: MIT
 *
 * Copyright (C) 2017-2021 WireGuard LLC. All Rights Reserved.
 */

package sdp

import (
//	"encoding/hex"
	"testing"
	"golang.zx2c4.com/wireguard/sdp"
)

func TestSM2(t *testing.T){
        sk1, err := sdp.NewPrivateKey()
	assertNil(t, err)

	sk2, err := sdp.NewPrivateKey()
	assertNil(t, err)

	pk1 := sk1.PublicKey()
	pk2 := sk2.PublicKey()

	ss1 := sk1.SharedSecret(pk2)
	ss2 := sk2.SharedSecret(pk1)

	if ss1 != ss2 {
		t.Fatal("Failed to compute shared secet")
	}
}
