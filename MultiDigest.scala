import scala.collection.mutable.HashMap
import org.bouncycastle.crypto._
import org.bouncycastle.crypto.digests._;

class MultiDigest(_digestContexts: List[Digest]) {
	var digestContexts = _digestContexts

  def update(data: Array[Byte]): MultiDigest = {
    digestContexts.foreach(_.update(data, 0, data.length))
		this
  }
	
	// FIXME: This assumes ASCII encoding.
	def update(data: String): MultiDigest = {
		update(data.map(_.toByte).toArray)
	}
	
	def update(is: java.io.InputStream): MultiDigest = {
		val bufferSize = 1024 * 1024
		val bb = new Array[Byte](bufferSize)
		val bis = new java.io.BufferedInputStream(is)
		var bytesRead = bis.read(bb, 0, bufferSize)
		while (bytesRead > 0) {
			digestContexts.foreach(_.update(bb, 0, bytesRead))
			bytesRead = bis.read(bb, 0, bufferSize)
		}
		this
	}
	
	def doFinal() = {
		var digestMap = new HashMap[String, String]
		digestContexts.foreach(
			x => {
				val result = new Array[Byte](x.getDigestSize())
				x.doFinal(result, 0)
				digestMap += x.getAlgorithmName() -> result.map("%02x" format _).mkString
			}
		)
		digestMap
	}
}

