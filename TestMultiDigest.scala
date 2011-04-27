import org.bouncycastle.crypto._
import org.bouncycastle.crypto.digests._;

// Runs a simple test. More extensive testing is done in STMultiDigest.scala.
object TestMultiDigest {
  def main(args: Array[String]) : Unit = {
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
		println(digestMap)
		assert(digestMap("MD5") == "3858f62230ac3c915f300c664312c63f")
		assert(digestMap("SHA-1") == "8843d7f92416211de9ebb963ff4ce28125932878")
		assert(digestMap("SHA-224") == "de76c3e567fca9d246f5f8d3b2e704a38c3c5e258988ab525f941db8")
		assert(digestMap("SHA-256") == "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2")
		assert(digestMap("SHA-384") == "3c9c30d9f665e74d515c842960d4a451c83a0125fd3de7392d7b37231af10c72ea58aedfcdf89a5765bf902af93ecf06")
		assert(digestMap("SHA-512") == "0a50261ebd1a390fed2bf326f2673c145582a6342d523204973d0219337f81616a8069b012587cf5635f6925f1b56c360230c19b273500ee013e030601bf2425")
	}
}