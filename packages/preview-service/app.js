'use strict'

var createError = require( 'http-errors' )
var express = require( 'express' )
var path = require( 'path' )
var cookieParser = require( 'cookie-parser' )
var logger = require( 'morgan' )

var indexRouter = require( './routes/index' )
var previewRouter = require( './routes/preview' )
var objectsRouter = require( './routes/objects' )

var app = express()

app.use( logger( 'dev' ) )
app.use( express.json() )
app.use( express.urlencoded( { extended: false } ) )
app.use( cookieParser() )
app.use( express.static( path.join( __dirname, 'public' ) ) )

app.use( '/', indexRouter )
app.use( '/preview', previewRouter )
app.use( '/objects', objectsRouter )

// catch 404 and forward to error handler
app.use( function( req, res, next ) {
  next( createError( 404 ) )
} )

// error handler
app.use( function( err, req, res, next ) {
  let errorText = err.message
  if ( req.app.get( 'env' ) === 'development' ) {
    errorText = `<html><body><pre>${err.message}: ${err.status}\n${err.stack}</pre></body></html>`
  }
  res.status( err.status || 500 )
  res.send( errorText )
} )

module.exports = app
