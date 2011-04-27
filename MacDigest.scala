import org.bouncycastle.crypto._
import org.bouncycastle.crypto.digests._;

class MacDigest(_name:String, _mac: Mac) extends Digest {
	val algorithmName = _name
	val mac = _mac
	
	def doFinal(bb: Array[Byte], offset: Int) = mac.doFinal(bb, offset)
	def getAlgorithmName = algorithmName
	def getDigestSize = mac.getMacSize
	def reset = mac.reset
	def update(b: Byte) = mac.update(b)
	def update(bb: Array[Byte], offset: Int, len: Int) = mac.update(bb, offset, len)
}
