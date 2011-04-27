BC=C:\\Users\\software\\.m2\\repository\\\org\\bouncycastle\\bcprov-jdk16\\1.45\\bcprov-jdk16-1.45.jar
SCALATEST=C:\\Scala\\scalatest-1.3\\scalatest-1.3.jar
COMPILEOPTS=-classpath .\;$(BC)
COMPILE=scalac
# The scala-test in sbaz appears to be scalacheck instead of ScalaTest
#TESTPATH=.\;scalatest-1.3.jar\;$(BC);C:\\Program\ Files\\Scala\\scala-2.8.1.final\\lib\\scala-library.jar
TESTPATH=.\;$(SCALATEST)\;$(BC)
TESTOPS=-classpath $(TESTPATH)

all: run

STMultiDigest.class: STMultiDigest.scala
	$(COMPILE) $(TESTOPS) STMultiDigest.scala

%.class : %.scala
	$(COMPILE) $(COMPILEOPTS) $<



run: MultiDigest.class TestMultiDigest.class
	scala $(COMPILEOPTS) TestMultiDigest

test: MultiDigest.class CRC32Digest.class MacDigest.class STMultiDigest.class 
	scala $(TESTOPS) org.scalatest.tools.Runner -p $(TESTPATH) -o -s STMultiDigest

clean:
	rm *.class