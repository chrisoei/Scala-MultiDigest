import java.util.zip.CRC32
import org.bouncycastle.crypto._
import org.bouncycastle.crypto.digests._;

// A BouncyCastle-compatible CRC32Digest created by wrapping java.util.zip.CRC32.

class CRC32Digest extends Digest {
	val crc32Context = new CRC32();
	
	def doFinal(bb: Array[Byte], start: Int):Int = {
		val result = crc32Context.getValue()
		// http://snippets.dzone.com/posts/show/93
		for (i <- 0 until 4) {
			bb(i + start) = (result >>> ((3 - i) * 8) & 0xFF).asInstanceOf[Byte]
		}
		return 0
	}
	
	def getAlgorithmName = "CRC32"
	
	def getDigestSize = 4;
	
	def reset = crc32Context.reset
	
	def update(in: Byte)
	{
		crc32Context.update(in)
	}
	
	def update(bb: Array[Byte], start: Int, length: Int) {
		crc32Context.update(bb, start, length)
	}
}
