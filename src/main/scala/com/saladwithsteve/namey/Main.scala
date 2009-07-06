package com.saladwithsteve.namey

import net.lag.configgy.{Config, ConfigMap, Configgy, RuntimeEnvironment}
import net.lag.extensions._
import net.lag.logging.Logger
import net.lag.naggati.IoHandlerActorAdapter
import org.apache.mina.filter.codec.ProtocolCodecFilter
import org.apache.mina.transport.socket.SocketAcceptor
import org.apache.mina.transport.socket.nio.{NioProcessor, NioDatagramAcceptor}
import java.net.InetSocketAddress
import java.util.concurrent.{CountDownLatch, Executors, ExecutorService, TimeUnit}
import scala.actors.{Actor, Scheduler}
import scala.actors.Actor._
import com.twitter.commons.Stats

/**
 * Simple DNS server.
 */
object Namey {
  private val log = Logger.get
  private val deathSwitch = new CountDownLatch(1)

  val runtime = new RuntimeEnvironment(getClass)

  var acceptorExecutor: ExecutorService = null
  var acceptor: NioDatagramAcceptor = null

  def main(args: Array[String]) {
    runtime.load(args)
    startup(Configgy.config)
  }

  def startup(config: Config) {
    val listenAddress = config.getString("listen_host", "0.0.0.0")
    val listenPort = config.getInt("listen_port", 9053)

    val maxThreads = config.getInt("max_threads", Runtime.getRuntime().availableProcessors * 2)
    System.setProperty("actors.maxPoolSize", maxThreads.toString)
    log.debug("max_threads=%d", maxThreads)

    // FIXME: make this configurable via Configgy
    val noop = new NoOpMailRouter(Map.empty)

    acceptorExecutor = Executors.newCachedThreadPool()
    //acceptor = new NioDatagramAcceptor(acceptorExecutor, new NioProcessor(acceptorExecutor))
    acceptor = new NioDatagramAcceptor(acceptorExecutor)

    acceptor.getFilterChain.addLast("codec", new ProtocolCodecFilter(dns.Codec.encoder, dns.Codec.decoder))
    acceptor.setHandler(new IoHandlerActorAdapter(session => new DnsHandler(session, config, noop)))
    acceptor.bind(new InetSocketAddress(listenAddress, listenPort))

    log.info("Listening on port %s", listenPort)

    actor {
      deathSwitch.await
    }
  }
}
