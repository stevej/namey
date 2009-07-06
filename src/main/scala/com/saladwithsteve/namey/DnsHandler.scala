/** Copyright 2009 Steve Jenson, licensed under the included Apache 2.0 License. */
package com.saladwithsteve.namey

import net.lag.configgy.{Config, Configgy, RuntimeEnvironment}
import net.lag.extensions._
import net.lag.logging.Logger
import net.lag.naggati.{IoHandlerActorAdapter, MinaMessage, ProtocolError}
import org.apache.mina.core.buffer.IoBuffer
import org.apache.mina.core.future.WriteFuture
import org.apache.mina.core.session.{IdleStatus, IoSession}
import java.io.IOException
import scala.actors.Actor
import scala.actors.Actor._
import scala.collection.mutable

/**
 * DnsHandler receives groups of commands and optionally data from the Codec supplied to Mina.
 *
 * @author Steve Jenson &lt;stevej@pobox.com&gt;
 */
class DnsHandler(val session: IoSession, val config: Config, val router: MailRouter) extends Actor {
  private val log = Logger.get

  val serverName = config.getString("server-name", "localhost")
  var sessionId = 0

  session.getConfig.setReadBufferSize(config.getInt("mina-read-buffer-size", 2048))
  IoHandlerActorAdapter.filter(session) -= classOf[MinaMessage.MessageSent]

  val idleTimeout = config.getInt("idle-timeout", 2500)
  session.getConfig.setIdleTime(IdleStatus.BOTH_IDLE, idleTimeout)

  start
  def act = {
    loop {
      react {
        case MinaMessage.MessageReceived(msg) =>
          handle(msg.asInstanceOf[dns.Request])

        case MinaMessage.ExceptionCaught(cause) => {
          cause.getCause match {
            case e: ProtocolError => writeResponse(e.getMessage + "\n")
            case _: IOException =>
              // FIXME: create proper session IDs for message tracking.
              log.debug("IO Exception on session %d: %s", sessionId, cause.getMessage)
            case _ =>
              // FIXME: create proper session IDs for message tracking.
              log.error(cause, "Exception caught on session %d with cause: %s", sessionId, cause.getMessage)
              //writeResponse("502 ERROR\n")
          }
          NameServerStats.sessionErrors.incr
          session.close
        }

        case MinaMessage.SessionClosed =>
          log.debug("End of session %d", sessionId)
          // abortAnyTransaction
          NameServerStats.closedSessions.incr
          exit()

        case MinaMessage.SessionIdle(status) =>
          log.debug("Idle timeout on session %s", sessionId)
          session.close

        case MinaMessage.SessionOpened =>
          sessionId = NameServerStats.totalSessions.incrementAndGet()
          log.debug("Session opened %d", sessionId)
          //writeResponse("220 %s SMTP\n".format(serverName))
      }
    }
  }

  private def writeResponse(out: Array[Byte]): WriteFuture = session.write(new dns.Response(IoBuffer.wrap(out)))

  private def writeResponse(out: String): WriteFuture = writeResponse(out.getBytes)

  private def writeResponse(out: String, data: Array[Byte]): WriteFuture = {
    val bytes = out.getBytes
    val buffer = IoBuffer.allocate(bytes.length + data.length + 7)
    buffer.put(bytes)
    buffer.put(data)
    buffer.flip
    NameServerStats.bytesWritten.incr(buffer.capacity)
    session.write(new dns.Response(buffer))
  }

  private def handle(req: dns.Request) = {
    println(req)
    writeResponse(Array(0x00.toByte))
  }

  def databody(req: dns.Request) {
    log.debug("handling databody in Thread %s", Thread.currentThread)
    //NameServerStats.nameResolutionLatency.time[Unit] { router(EmailBuilder(req.data)) }
    writeResponse("250 Safely handled. txn %s\n".format(0L))
  }

  def stats(req: dns.Request) {
    var report = new mutable.ArrayBuffer[(String, Long)]
    report += (("bytesWritten", NameServerStats.bytesWritten()))
    report += (("totalSessions", NameServerStats.totalSessions.intValue()))
    report += (("closedSessions", NameServerStats.closedSessions()))
    report += (("sessionErrors", NameServerStats.sessionErrors()))
    val routerTiming = NameServerStats.nameResolutionLatency.getCountMinMaxAvg(false)
    report += (("mailRouterLatencyCount", routerTiming._1))
    report += (("mailRouterLatencyMin", routerTiming._2))
    report += (("mailRouterLatencyMax", routerTiming._3))
    report += (("mailRouterLatencyAvg", routerTiming._4))

    writeResponse(report.mkString("", "\n", "\n"))
  }
}
