package sha3test

// Expected outputs taken from
//
// For SHA224, SHA256, SHA384, SHA512
// http://www.di-mgt.com.au/sha_testvectors.html
// I matched some to
// http://csrc.nist.gov/groups/ST/toolkit/examples.html
// but not all.
//
// FOR SHAKE128, SHAKE256
// http://csrc.nist.gov/groups/ST/toolkit/examples.html

import (
	"encoding/hex"
	"testing"

	"golang.org/x/crypto/sha3"
)

type shaFunc func([]byte) []byte

var byteArray0 [0]byte
var byteArray3 [3]byte
var byteArray56 [56]byte
var byteArray112 [112]byte
var byteArray97 [125000]byte

func TestSHA224(t *testing.T) {

	shaCheck(sha224(), byteArray0[:],
		"",
		"6b4e03423667dbb73b6e15454f0eb1abd4597f9a1b078e3f5b5a6bc7",
		t)

	shaCheck(sha224(), byteArray3[:],
		"abc",
		"e642824c3f8cf24ad09234ee7d3c766fc9a3a5168d0c94ad73b46fdf",
		t)

	shaCheck(sha224(), byteArray56[:],
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"8a24108b154ada21c9fd5574494479ba5c7e7ab76ef264ead0fcce33",
		t)

	shaCheck(sha224(), byteArray112[:],
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"543e6868e1666c1a643630df77367ae5a62a85070a51c14cbf665cbc",
		t)

}

func TestSHA256(t *testing.T) {

	shaCheck(sha256(), byteArray0[:],
		"",
		"a7ffc6f8bf1ed76651c14756a061d662f580ff4de43b49fa82d80a4b80f8434a",
		t)

	shaCheck(sha256(), byteArray3[:],
		"abc",
		"3a985da74fe225b2045c172d6bd390bd855f086e3e9d525b46bfe24511431532",
		t)

	shaCheck(sha256(), byteArray56[:],
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"41c0dba2a9d6240849100376a8235e2c82e1b9998a999e21db32dd97496d3376",
		t)

	shaCheck(sha256(), byteArray112[:],
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"916f6061fe879741ca6469b43971dfdb28b1a32dc36cb3254e812be27aad1d18",
		t)

}

func TestSHA384(t *testing.T) {

	shaCheck(sha384(), byteArray0[:],
		"",
		"0c63a75b845e4f7d01107d852e4c2485c51a50aaaa94fc61995e71bbee983a2ac3713831264adb47fb6bd1e058d5f004",
		t)

	shaCheck(sha384(), byteArray3[:],
		"abc",
		"ec01498288516fc926459f58e2c6ad8df9b473cb0fc08c2596da7cf0e49be4b298d88cea927ac7f539f1edf228376d25",
		t)

	shaCheck(sha384(), byteArray56[:],
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"991c665755eb3a4b6bbdfb75c78a492e8c56a22c5c4d7e429bfdbc32b9d4ad5aa04a1f076e62fea19eef51acd0657c22",
		t)

	shaCheck(sha384(), byteArray112[:],
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"79407d3b5916b59c3e30b09822974791c313fb9ecc849e406f23592d04f625dc8c709b98b43b3852b337216179aa7fc7",
		t)

}

func TestSHA512(t *testing.T) {

	shaCheck(sha512(), byteArray0[:],
		"",
		"a69f73cca23a9ac5c8b567dc185a756e97c982164fe25859e0d1dcc1475c80a615b2123af1f5f94c11e3e9402c3ac558f500199d95b6d3e301758586281dcd26",
		t)

	shaCheck(sha512(), byteArray3[:],
		"abc",
		"b751850b1a57168a5693cd924b6b096e08f621827444f70d884f5d0240d2712e10e116e9192af3c91a7ec57647e3934057340b4cf408d5a56592f8274eec53f0",
		t)

	shaCheck(sha512(), byteArray56[:],
		"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq",
		"04a371e84ecfb5b8b77cb48610fca8182dd457ce6f326a0fd3d7ec2f1e91636dee691fbe0c985302ba1b0d8dc78c086346b533b49c030d99a27daf1139d6e75e",
		t)

	shaCheck(sha512(), byteArray112[:],
		"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu",
		"afebb2ef542e6579c50cad06d2e578f9f8dd6881d7dc824d26360feebf18a4fa73e3261122948efcfd492e74e82e2189ed0fb440d187f382270cb455f21dd185",
		t)

}

func TestSHAKE128(t *testing.T) {

	shaCheck(shake128(), byteArray0[:],
		"",
		"7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef263cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32def58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c922a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b1de33fd75081f592305f2e4526edc09631b10958f464d889f31ba010250fda7f1368ec2967fc84ef2ae9aff268e0b1700affc6820b523a3d917135f2dff2ee06bfe72b3124721d4a26c04e53a75e30e73a7a9c4a95d91c55d495e9f51dd0b5e9d83c6d5e8ce803aa62b8d654db53d09b8dcff273cdfeb573fad8bcd45578bec2e770d01efde86e721a3f7c6cce275dabe6e2143f1af18da7efddc4c7b70b5e345db93cc936bea323491ccb38a388f546a9ff00dd4e1300b9b2153d2041d205b443e41b45a653f2a5c4492c1add544512dda2529833462b71a41a45be97290b6f",
		t)

}

func TestSHAKE256(t *testing.T) {

	shaCheck(shake256(), byteArray0[:],
		"",
		"46b9dd2b0ba88d13233b3feb743eeb243fcd52ea62b81b82b50c27646ed5762fd75dc4ddd8c0f200cb05019d67b592f6fc821c49479ab48640292eacb3b7c4be141e96616fb13957692cc7edd0b45ae3dc07223c8e92937bef84bc0eab862853349ec75546f58fb7c2775c38462c5010d846c185c15111e595522a6bcd16cf86f3d122109e3b1fdd943b6aec468a2d621a7c06c6a957c62b54dafc3be87567d677231395f6147293b68ceab7a9e0c58d864e8efde4e1b9a46cbe854713672f5caaae314ed9083dab4b099f8e300f01b8650f1f4b1d8fcf3f3cb53fb8e9eb2ea203bdc970f50ae55428a91f7f53ac266b28419c3778a15fd248d339ede785fb7f5a1aaa96d313eacc890936c173cdcd0fab882c45755feb3aed96d477ff96390bf9a66d1368b208e21f7c10d04a3dbd4e360633e5db4b602601c14cea737db3dcf722632cc77851cbdde2aaf0a33a07b373445df490cc8fc1e4160ff118378f11f0477de055a81a9eda57a4a2cfb0c83929d310912f729ec6cfa36c6ac6a75837143045d791cc85eff5b21932f23861bcf23a52b5da67eaf7baae0f5fb1369db78f3ac45f8c4ac5671d85735cdddb09d2b1e34a1fc066ff4a162cb263d6541274ae2fcc865f618abe27c124cd8b074ccd516301b91875824d09958f341ef274bdab0bae316339894304e35877b0c28a9b1fd166c796b9cc258a064a8f57e27f2a",
		t)

}

func sha224() func(b []byte) []byte {
	return func(b []byte) []byte {
		hash := sha3.Sum224(b)
		return hash[:]
	}
}

func sha256() func(b []byte) []byte {
	return func(b []byte) []byte {
		hash := sha3.Sum256(b)
		return hash[:]
	}
}

func sha384() func(b []byte) []byte {
	return func(b []byte) []byte {
		hash := sha3.Sum384(b)
		return hash[:]
	}
}

func sha512() func(b []byte) []byte {
	return func(b []byte) []byte {
		hash := sha3.Sum512(b)
		return hash[:]
	}
}

func shake128() func(b []byte) []byte {
	return func(b []byte) []byte {
		hash := make([]byte, 512)
		sha3.ShakeSum128(hash, b)
		return hash
	}
}

func shake256() func(b []byte) []byte {
	return func(b []byte) []byte {
		hash := make([]byte, 512)
		sha3.ShakeSum256(hash, b)
		return hash
	}
}

func shaCheck(sha shaFunc, byteArray []byte, inputString, expectedOutput string, t *testing.T) {
	copy(byteArray[:], inputString)
	hash := sha(byteArray[:])
	hexString := hex.EncodeToString(hash[:])
	if hexString != expectedOutput {
		t.Fatalf("Expected %s. but got %s", expectedOutput, hexString)
	}
}
