/* istanbul ignore file */
'use strict'

const passport = require( 'passport' )
const OIDCStrategy = require( 'passport-azure-ad' ).OIDCStrategy
const URL = require( 'url' ).URL
const debug = require( 'debug' )
const appRoot = require( 'app-root-path' )
const { findOrCreateUser, getUserByEmail } = require( `${appRoot}/modules/core/services/users` )
const { getServerInfo } = require( `${appRoot}/modules/core/services/generic` )
const { validateInvite, useInvite } = require( `${appRoot}/modules/serverinvites/services` )

const config = require( `${appRoot}/hxaConfig.json` )
// rht1:option: require( 'dotenv' ).config( { path: `${appRoot}/hxaConfig.json` } )

module.exports = async ( app, session, sessionStorage, finalizeAuth ) => {

  // 
  // rht: https://www.npmjs.com/package/passport-azure-ad#41-oidcstrategy
  //      https://github.com/AzureAD/passport-azure-ad
  //      https://docs.microsoft.com/en-us/samples/azure-samples/active-directory-b2c-javascript-nodejs-webapi/nodejs-web-api-azure-ad/ 
  //      https://stackoverflow.com/questions/45197322/microsoft-ad-b2c-issue-policy-is-missing
  //      SEE: https://github.com/AzureADQuickStarts/B2C-WebApp-OpenIDConnect-NodeJS and https://github.com/AzureADQuickStarts/B2C-WebApp-OpenIDConnect-NodeJS/blob/master/config.js
  //      https://github.com/AzureAD/passport-azure-ad/issues/418
  //
  let strategy = new OIDCStrategy( {
    identityMetadata: `https://${config.credentials.tenantName}.b2clogin.com/${config.credentials.tenantName}.onmicrosoft.com/${config.policies.policyName}/${config.metadata.version}/${config.metadata.discovery}/?p=${config.policies.policyName}`,
    clientID: config.credentials.clientID,
    responseType: 'code id_token',
    responseMode: 'form_post',
    isB2C: config.settings.isB2C,
    issuer: `https://${config.credentials.tenantName}.b2clogin.com/${config.credentials.tenantId}/${config.metadata.version}/`,
    redirectUrl: new URL( '/auth/azure/callback', config.settings.redirectUrl).toString(),
    allowHttpForRedirectUrl: true,
    clientSecret: config.credentials.clientSecret,
    scope: [ 'profile', 'email', 'openid' ],
    loggingLevel: process.env.NODE_ENV === 'development' ? 'info' : 'error',
    passReqToCallback: true
  }, async ( req, iss, sub, profile, accessToken, refreshToken, done ) => {
    debug( 'speckle:startup' )( "rht-1.3: tmptst :") 
    done( null, profile )
  } )

  passport.use( strategy )

  app.get( '/auth/azure', session, sessionStorage, passport.authenticate( 'azuread-openidconnect', { 
    failureRedirect: '/error?message=Failed to authenticate.' } ) )
  app.post( '/auth/azure/callback',
    session,
    passport.authenticate( 'azuread-openidconnect', { failureRedirect: '/error?message=Failed to authenticate.' } ),
    async ( req, res, next ) => {
      const serverInfo = await getServerInfo()

      try {
        let user = {
          email: req.user._json.emails[0],
          name:  req.user._json.name || req.user.displayName
        }

        if ( req.session.suuid )
          user.suuid = req.session.suuid

        let existingUser
        existingUser = await getUserByEmail( { email: user.email } )

        // if there is an existing user, go ahead and log them in (regardless of
        // whether the server is invite only or not).
        if ( existingUser ) {
          let myUser = await findOrCreateUser( { user: user, rawProfile: req.user._json } )
          // ID is used later for verifying access token
          req.user.id = myUser.id
          return next()
        }

        // if the server is not invite only, go ahead and log the user in.
        if ( !serverInfo.inviteOnly ) {
          let myUser = await findOrCreateUser( { user: user, rawProfile: req.user._json } )
          // ID is used later for verifying access token
          req.user.id = myUser.id
          return next()
        }

        // if the server is invite only and we have no invite id, throw.
        if ( serverInfo.inviteOnly && !req.session.inviteId ) {
          throw new Error( 'This server is invite only. Please provide an invite id.' )
        }

        // validate the invite
        const validInvite = await validateInvite( { id: req.session.inviteId, email: user.email } )
        if ( !validInvite )
          throw new Error( 'Invalid invite.' )

        // create the user
        let myUser = await findOrCreateUser( { user: user, rawProfile: req.user._json } )
        // ID is used later for verifying access token
        req.user.id = myUser.id

        // use the invite
        await useInvite( { id: req.session.inviteId, email: user.email } )

        // return to the auth flow
        return next()
      } catch ( err ) {
        debug( 'speckle:errors' )( err )
        return next()
      }
    },
    finalizeAuth
  )

  return {
    id: 'azuread',
    name: process.env.AZURE_AD_ORG_NAME || 'Microsoft',
    icon: 'mdi-microsoft',
    color: 'blue darken-3',
    url: '/auth/azure',
    callbackUrl: new URL( '/auth/azure/callback', process.env.CANONICAL_URL ).toString()
  }
}
