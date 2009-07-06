package com.saladwithsteve.namey.dns

import org.apache.mina.core.buffer.IoBuffer
import org.apache.mina.core.session.{IdleStatus, IoSession}
import org.apache.mina.filter.codec._
import net.lag.extensions._
import net.lag.logging.Logger
import net.lag.naggati.{COMPLETE, Decoder, End, NEED_DATA, ProtocolError, Step}
import net.lag.naggati.Steps._
import scala.collection.mutable.ListBuffer

case class Request(txnId: Int, qr: QR, query: QueryType, recursion: Recursion,
                   questions: List[Question], answers: List[Answer],
                   authorities: List[Authority], additional: List[Additional])

case class Response(data: IoBuffer)

trait QR
case object QueryQR extends QR
case object ResponseQR extends QR

trait QueryType
case object Standard extends QueryType
case object Inverse extends QueryType
case object Status extends QueryType

trait Recursion
case object Recursive extends Recursion
case object Iterative extends Recursion

case class Question(qname: String, qtype: Record, qclass: QClass)

trait Record
case object ARecord extends Record
case object NSRecord extends Record
case object CNAMERecord extends Record
case object HINFORecord extends Record
case object MXRecord extends Record
case object AXFRRecord extends Record
case object ANYRecord extends Record
case object UnknownRecord extends Record

trait QClass
case object InternetClass extends QClass
case object UnknownClass extends QClass

case class Answer()
case class Authority()
case class Additional()

object Codec {
  private val log = Logger.get

  val encoder = new ProtocolEncoder {
    def encode(session: IoSession, message: AnyRef, out: ProtocolEncoderOutput) = {
      val buffer = message.asInstanceOf[Response].data
      NameServerStats.bytesWritten.incr(buffer.remaining)
      out.write(buffer)
    }

    def dispose(session: IoSession): Unit = {
      // nothing.
    }
  }

  // RFC 1035: 512 bytes is the maximum size of a DNS datagram.
  def decoder = new Decoder(readByteBuffer(12) { buffer =>
    println("buffer %s of length: %s".format(new String(buffer), buffer.length))
    val txnId = (buffer(0).toInt << 8) + buffer(1).toInt
    println("txnId: " + txnId)
    // Parse the flags portion of DNS request
    val qr = (buffer(2) & 0x80) match {
      case 0x00 => QueryQR
      case 0x80 => ResponseQR
      case x => throw new ProtocolError("unknown QR value: " + x)
    }
    println("qr: " + qr)

    val query = ((buffer(2) >> 3) & 0x70) match {
      case 0 => Standard
      case 1 => Inverse
      case 2 => Status
      case x => throw new ProtocolError("unknown Query value: " + x)
    }

    val recursion = (buffer(2) & 0x01) match {
      case 1 => Recursive
      case 0 => Iterative
      case x => throw new ProtocolError("unknown Recursion value: " + x)
    }
    println("recursion: " + recursion)

    val questionsCount  = (buffer(4).toInt  << 8) + buffer(5).toInt
    println("questionsCount: " + questionsCount)
    val answerCount     = (buffer(6).toInt  << 8) + buffer(7).toInt
    val authorityCount  = (buffer(8).toInt  << 8) + buffer(9).toInt
    val additionalCount = (buffer(10).toInt << 8) + buffer(11).toInt

    log.debug("txnId:%s, questionsCount:%s, answerCount:%s, authorityCount:%s, additionalCount:%s", txnId, questionsCount, answerCount, authorityCount, additionalCount)

    log.debug("going to read %s questions", questionsCount)
    if (questionsCount > 256) {
      throw new ProtocolError("too many questions")
    }

    val qs = new ListBuffer[Question]
    var qtype: Record = null
    var qclass: QClass = null

    readDelimiterBuffer(0x00.toByte) { buffer =>
      log.debug("read buffer: %s of length: %s", new String(buffer), buffer.length)
      var nameLen = buffer(0).toInt
      var pos = 1
      var qname = new StringBuilder()
      while (nameLen > 0) {
        qname.append(new String(buffer.slice(pos, pos + nameLen)))
        qname.append(".")
        pos += nameLen
        nameLen = buffer(pos)
      }

      readByteBuffer(2) { buffer =>
        log.debug("read 2-byte buffer: %s", new String(buffer))
        val int16 = (buffer(0).toInt << 8) + buffer(1).toInt
        qtype = int16 match {
          case 1   => ARecord
          case 5   => NSRecord
          case 12  => CNAMERecord
          case 13  => HINFORecord
          case 15  => MXRecord
          case 252 => AXFRRecord
          case 255 => ANYRecord
          case _   => UnknownRecord
        }

        readByteBuffer(2) { buffer =>
          val int16 = (buffer(0).toInt << 8) + buffer(1).toInt
          qclass = int16 match {
            case 1 => InternetClass
            case _ => UnknownClass
          }

          qs.append(Question(qname.toString, qtype, qclass))

          if (questionsCount > 1) {
            //readQuestions(questionsCount - 1); End
            log.error("only grabbed one question, missed the rest.")
            End
          } else {
            End
          }
        }
      }
    }

    val questions = qs.toList

    // Read in answerCount (should always be 0 for a dns query)
    val answers = readAnswers(answerCount)
    // Read in authorityCount
    val authorities = readAuthorities(authorityCount)
    // Read in additionalCount
    val additional = readAdditional(additionalCount)
    state.out.write(new Request(txnId, qr, query, recursion, questions, answers, authorities, additional))
    End
  })

  def readQuestions(count: Int): List[Question] = {
    log.debug("going to read %s questions", count)
    if (count > 256) {
      throw new ProtocolError("too many questions")
    }

    val qs = new ListBuffer[Question]
    var qtype: Record = null
    var qclass: QClass = null

    readDelimiterBuffer(0x00.toByte) { buffer =>
      var nameLen = buffer(0).toInt
      var pos = 1
      var qname = new StringBuilder()
      while (nameLen > 0) {
        qname.append(new String(buffer.slice(pos, pos + nameLen)))
        qname.append(".")
        pos += nameLen
        nameLen = buffer(pos)
      }

      readByteBuffer(2) { buffer =>
        val int16 = (buffer(0).toInt << 8) + buffer(1).toInt
        qtype = int16 match {
          case 1   => ARecord
          case 5   => NSRecord
          case 12  => CNAMERecord
          case 13  => HINFORecord
          case 15  => MXRecord
          case 252 => AXFRRecord
          case 255 => ANYRecord
          case _   => UnknownRecord
        }

        readByteBuffer(2) { buffer =>
          val int16 = (buffer(0).toInt << 8) + buffer(1).toInt
          qclass = int16 match {
            case 1 => InternetClass
            case _ => UnknownClass
          }

          qs.append(Question(qname.toString, qtype, qclass))

          if (count > 1) {
            readQuestions(count - 1); End
          } else {
            End
          }
        }
      }
    }
    qs.toList
  }


  def _readQuestions(count: Int): List[Question] = {
    if (count > 100 || count < 0) {
      log.error("received invalid question count, returning empty list")
      return Nil
    }
    println("going to read %s questions".format(count))
    val qs = new ListBuffer[Question]
    for (i <- 0 to count) {
      var qname = new StringBuilder()
      var names = 0
      readByteBuffer(1) { bytes => names = bytes(0).toInt; End }
      println("reading %s names".format(names))
      while (names > 0) {
        readByteBuffer(names) { buffer =>
          qname.append(new String(buffer))
          qname.append(".")
          End
        }
        readByteBuffer(1) { bytes => names = bytes(0).toInt; End }
      }

      var qtype: Record = null
      readByteBuffer(2) { buffer =>
        val int16 = (buffer(0).toInt << 8) + buffer(1).toInt
        qtype = int16 match {
          case 1   => ARecord
          case 5   => NSRecord
          case 12  => CNAMERecord
          case 13  => HINFORecord
          case 15  => MXRecord
          case 252 => AXFRRecord
          case 255 => ANYRecord
          case _   => UnknownRecord
        }
        End
      }

      var qclass: QClass = null
      readByteBuffer(2) { buffer =>
        val int16 = (buffer(0).toInt << 8) + buffer(1).toInt
        qclass = int16 match {
          case 1 => InternetClass
          case _ => UnknownClass
        }
        End
      }

      qs.append(Question(qname.toString, qtype, qclass))
    }
    qs.toList
  }

  def readAnswers(count: Int): List[Answer] = {
    Nil
  }

  def readAuthorities(count: Int): List[Authority] = {
    Nil
  }

  def readAdditional(count: Int): List[Additional] = {
    Nil
  }

}
