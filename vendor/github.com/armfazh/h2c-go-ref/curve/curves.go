package curve

import (
	"math/big"

	GF "github.com/armfazh/h2c-go-ref/field"
	C "github.com/armfazh/tozan-ecc/curve"
)

type ID string

const (
	P256             ID = "P256"
	P384             ID = "P384"
	P521             ID = "P521"
	Curve25519       ID = "Curve25519"
	Curve448         ID = "Curve448"
	Edwards25519     ID = "Edwards25519"
	Edwards448       ID = "Edwards448"
	SECP256K1        ID = "SECP256K1"
	SECP256K1_3ISO   ID = "SECP256K1_3ISO"
	BLS12381G1       ID = "BLS12381G1"
	BLS12381G1_11ISO ID = "BLS12381G1_11ISO"
	BLS12381G2       ID = "BLS12381G2"
	BLS12381G2_3ISO  ID = "BLS12381G2_3ISO"
)

// Get returns a specific instance of an elliptic curve.
func (id ID) Get() C.EllCurve {
	switch id {
	case P256:
		f := GF.P256.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("-3"),
			f.Elt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
			str2bigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
			big.NewInt(1))
	case P384:
		f := GF.P384.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("-3"),
			f.Elt("0xb3312fa7e23ee7e4988e056be3f82d19181d9c6efe8141120314088f5013875ac656398d8a2ed19d2a85c8edd3ec2aef"),
			str2bigInt("0xffffffffffffffffffffffffffffffffffffffffffffffffc7634d81f4372ddf581a0db248b0a77aecec196accc52973"),
			big.NewInt(1))
	case P521:
		f := GF.P521.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("-3"),
			f.Elt("0x051953eb9618e1c9a1f929a21a0b68540eea2da725b99b315f3b8b489918ef109e156193951ec7e937b1652c0bd3bb1bf073573df883d2c34f1ef451fd46b503f00"),
			str2bigInt("0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffd15b6c64746fc85f736b8af5e7ec53f04fbd8c4569a8f1f4540ea2435f5180d6b"),
			big.NewInt(1))
	case SECP256K1:
		f := GF.P256K1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Zero(),
			f.Elt("7"),
			str2bigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
			big.NewInt(1))
	case SECP256K1_3ISO:
		f := GF.P256K1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533"),
			f.Elt("1771"),
			str2bigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
			big.NewInt(1))
	case Curve25519:
		f := GF.P25519.Get()
		return C.Montgomery.New(string(id), f,
			f.Elt("486662"),
			f.One(),
			str2bigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
			big.NewInt(8))
	case Edwards25519:
		f := GF.P25519.Get()
		return C.TwistedEdwards.New(string(id), f,
			f.Elt("-1"),
			f.Elt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
			str2bigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
			big.NewInt(8))
	case Curve448:
		f := GF.P448.Get()
		return C.Montgomery.New(string(id), f,
			f.Elt("156326"),
			f.One(),
			str2bigInt("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"),
			big.NewInt(4))
	case Edwards448:
		f := GF.P448.Get()
		return C.TwistedEdwards.New(string(id), f,
			f.One(),
			f.Elt("-39081"),
			str2bigInt("0x3fffffffffffffffffffffffffffffffffffffffffffffffffffffff7cca23e9c44edb49aed63690216cc2728dc58f552378c292ab5844f3"),
			big.NewInt(4))
	case BLS12381G1:
		f := GF.BLS12381G1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Zero(),
			f.Elt(4),
			str2bigInt("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
			str2bigInt("0xd201000000010001"))
	case BLS12381G1_11ISO:
		f := GF.BLS12381G1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d"),
			f.Elt("0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0"),
			str2bigInt("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
			str2bigInt("0xd201000000010001"))
	case BLS12381G2:
		f := GF.BLS12381G2.Get()
		return C.Weierstrass.New(string(id), f,
			f.Zero(),
			f.Elt([]interface{}{4, 4}),
			str2bigInt("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"),
			str2bigInt("0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551"))
	case BLS12381G2_3ISO:
		f := GF.BLS12381G2.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt([]interface{}{0, 240}),
			f.Elt([]interface{}{1012, 1012}),
			str2bigInt("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"),
			str2bigInt("0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551"))
	default:
		panic("curve not supported")
	}
}

func str2bigInt(s string) *big.Int {
	n := new(big.Int)
	if _, ok := n.SetString(s, 0); !ok {
		panic("error setting the number")
	}
	return n
}
