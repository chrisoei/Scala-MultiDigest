import org.scalatest.FunSuite

import org.bouncycastle.crypto.digests._;
import org.bouncycastle.crypto.macs.HMac;
import org.bouncycastle.crypto.params.KeyParameter;

class STMultiDigest extends FunSuite {
	test("MD5 is invoked on foobar") {
		assert(new MultiDigest(List(new MD5Digest())).update(
			Array[Byte]( 102, 111, 111, 98, 97, 114)			// "foobar"
			).doFinal()("MD5") == "3858f62230ac3c915f300c664312c63f")
	}

	test("SHA-1 is invoked on foobar") {
		val m = new MultiDigest(List(new SHA1Digest()))
		m.update(Array[Byte]( 102, 111, 111, 98, 97, 114)) // "foobar"
		val digestMap = m.doFinal
		assert(digestMap("SHA-1") == "8843d7f92416211de9ebb963ff4ce28125932878")
	}
	
	test("SHA-224 is invoked on foobar") {
		val m = new MultiDigest(List(new SHA224Digest()))
		m.update(Array[Byte]( 102, 111, 111, 98, 97, 114)) // "foobar"
		val digestMap = m.doFinal
		assert(digestMap("SHA-224") == "de76c3e567fca9d246f5f8d3b2e704a38c3c5e258988ab525f941db8")
	}
	
	test("SHA-256 is invoked on foobar") {
		val m = new MultiDigest(List(new SHA256Digest()))
		m.update(Array[Byte]( 102, 111, 111, 98, 97, 114)) // "foobar"
		val digestMap = m.doFinal
		assert(digestMap("SHA-256") == "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a39607" +
			"14caef0c4f2")
	}
	
	test("SHA-384 is invoked on foobar") {
		val m = new MultiDigest(List(new SHA384Digest()))
		m.update(Array[Byte]( 102, 111, 111, 98, 97, 114)) // "foobar"
		val digestMap = m.doFinal
		assert(digestMap("SHA-384") == "3c9c30d9f665e74d515c842960d4a451c83a0125fd3de7392d7b3" +
			"7231af10c72ea58aedfcdf89a5765bf902af93ecf06")
	}
	
	test("SHA-512 is invoked on foobar") {
		val m = new MultiDigest(List(new SHA512Digest()))
		m.update(Array[Byte]( 102, 111, 111, 98, 97, 114)) // "foobar"
		val digestMap = m.doFinal
		assert(digestMap("SHA-512") == "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0" +
			"219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425")
	}
	
	test("Split update") {
		val m = new MultiDigest(List(new MD5Digest()))
		m.update(Array[Byte]( 102, 111, 111)) // "foo"
		m.update(Array[Byte]( 98, 97, 114)) // "bar"
		val digestMap = m.doFinal
		assert(digestMap("MD5") == "3858f62230ac3c915f300c664312c63f")
	}
	
	test("Update on zero-sized array") {
		val m = new MultiDigest(List(new MD5Digest()))
		m.update(Array[Byte]())
		val digestMap = m.doFinal
		assert(digestMap("MD5") == "d41d8cd98f00b204e9800998ecf8427e")
	}
	
	test("Same as TestMultiDigest") {
			var m = new MultiDigest(List(
			new MD5Digest(), 
			new SHA1Digest(),
			new SHA224Digest(),
			new SHA256Digest(),
			new SHA384Digest(),
			new SHA512Digest()
		))
		m.update(Array[Byte]( 102, 111, 111)) // "foo"
		m.update(Array[Byte]()) // make sure updating with empty data works
		m.update(Array[Byte]( 98, 97, 114)) // "bar"
		val digestMap = m.doFinal
		assert(digestMap("MD5") == "3858f62230ac3c915f300c664312c63f")
		assert(digestMap("SHA-1") == "8843d7f92416211de9ebb963ff4ce28125932878")
		assert(digestMap("SHA-224") == "de76c3e567fca9d246f5f8d3b2e704a38c3c5e258988ab525f941db8")
		assert(digestMap("SHA-256") == "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714c" +
			"aef0c4f2")
		assert(digestMap("SHA-384") == "3c9c30d9f665e74d515c842960d4a451c83a0125fd3de7392d7b3723" +
			"1af10c72ea58aedfcdf89a5765bf902af93ecf06")
		assert(digestMap("SHA-512") == "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219" +
			"337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425")
	}
	
	test("RIPEMD-160 invoked on quick brown fox") {
		val m = new MultiDigest(List(new RIPEMD160Digest()))
		m.update("The quick brown fox jumps over the lazy dog")
		val digestMap = m.doFinal
		// This result is from http://en.wikipedia.org/wiki/RIPEMD
		assert(digestMap("RIPEMD160") == "37f332f68db77bd9d7edd4969571ad671cf9dd3b")
	}
	
	test("Whirlpool invoked on quick brown fox") {
		val m = new MultiDigest(List(new WhirlpoolDigest()))
		m.update("The quick brown fox jumps over the lazy dog")
		val digestMap = m.doFinal
		// This result is from http://en.wikipedia.org/wiki/Whirlpool_%28cryptography%29
		assert(digestMap("Whirlpool") == ("B97DE512E91E3828B40D2B0FDCE9CEB3C4A71F9BEA8D88E75C4FA" +
			"854DF36725FD2B52EB6544EDCACD6F8BEDDFEA403CB55AE31F03AD62A5EF54E42EE82C3FB35").toLowerCase)
	}
	
	test("MD4 invoked on quick brown fox") {
		val m = new MultiDigest(List(new MD4Digest()))
		m.update("The quick brown fox jumps over the lazy dog")
		val digestMap = m.doFinal
		// This result is from http://en.wikipedia.org/wiki/MD4
		assert(digestMap("MD4") == "1bee69a46ba811185c194762abaeae90")
	}

	test("CRC32 invoked on foobar") {
		val m = new MultiDigest(List(new CRC32Digest()))
		m.update("foobar")
		val digestMap = m.doFinal()
		// This result comes from Filekyrie 1.4.2.
		assert(digestMap("CRC32") == "9ef61f95")
	}
	
	test("HMAC_SHA1 invoked") {
		val hm = new HMac(new SHA1Digest())
		hm.init(new KeyParameter("foobar".getBytes("UTF-8")))
		assert(new MultiDigest(List(new MacDigest("HMAC_SHA1", hm))).update("barfoo").doFinal()("HMAC_SHA1")=="5817679313a780d2b540acd681af4fe71f225052")		
	}
	
	test("Invoking on an ASCII textfile") {
		assert(
			new MultiDigest(List(new MD5Digest()))
				.update(new java.io.FileInputStream("test.txt")).doFinal()("MD5") 
				== "6cd3556deb0da54bca060b4c39479839")
//		val digestMap = m.doFinal()
//		assert(digestMap("MD5") == "6cd3556deb0da54bca060b4c39479839")
	}
	
	test("Invoking on a binary file") {
		val m = new MultiDigest(List(new MD5Digest()))
		m.update(new java.io.FileInputStream("test.dat"))
		val digestMap = m.doFinal()
		assert(digestMap("MD5") == "f5c8e3c31c044bae0e65569560b54332")
	}

}