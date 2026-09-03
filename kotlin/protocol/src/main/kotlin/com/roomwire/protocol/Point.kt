package com.roomwire.protocol

/**
 * A position, in whatever space the caller is working in.
 *
 * The Swift side uses CGPoint for this and gets it from CoreGraphics; nothing
 * about a pair of doubles needs a graphics framework, so here it is spelled out.
 * Both the pointer glide and the button-mask contract take and return these.
 */
data class Point(val x: Double, val y: Double)
