/** Copyright 2009 Steve Jenson under the Apache 2.0 License */
package com.saladwithsteve.namey

import com.twitter.commons.Stats.Counter
import com.twitter.commons.Stats.Timing
import java.util.concurrent.atomic.AtomicInteger

object NameServerStats {
  val bytesWritten = new Counter
  val totalSessions = new AtomicInteger(0)
  val closedSessions = new Counter
  val sessionErrors = new Counter
  val nameResolutionLatency = new Timing
}
