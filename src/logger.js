
const color = require('./consoleColors.js')
const errorHeader = `${color.FgRed}========[ node-gpoauth error ]=========${color.Reset}\n`

/**
 * Logger
 *
 * Provide funcions for logging message to STDOUT.
 *
 * @param {Boolean} DEBUG - print out debug logs to STDOUT
 */
module.exports = function(DEBUG){

  /*
   * TODO:
   *  We should use formal errors (seporate file) so we can
   *  do type checking against them in test cases.
   */

  /**
   * Print degug information.
   *
   * NOTE:
   *   if debug is falsy nothing will be output to STDOUT by this command.
   *
   * @param {...*} args - data to log to console
   */
  function debug(/* arguments */){
    if(DEBUG === true || DEBUG === 'true')
      console.log.apply(this, [`${color.FgGreen}[${timeWithMilliseconds()}] ${color.Reset}`].concat(Array.prototype.slice.call(arguments)))
  }

  function timeWithMilliseconds(){
    const d = new Date();
    return `${d.toLocaleDateString()} ${d.toLocaleTimeString()}.${d.getMilliseconds()}`
  }

  /**
   * Abbreviate an Access or Refresh token for easy readability.
   *
   * @param {String} token
   * @return {String}
   */
  function tokenDemo(token){
    const len = token && token.length
    return len ?
          `${token.substring(0,4)}..[${len}]..${token.substring(len-4)}` :
          '[No token]'
  }

  /**
   * Formats an error with the pretty header.
   *
   * @param {String} msg
   * @param {Error} err
   */
  function formalError(msg, err){
    return new Error(`${errorHeader}\n${msg}\n\n${err}`)
  }

  /**
   * Formats an error with pretty header and footer containg information
   * pointing back to the node-gpoauth documentation.
   *
   * @param {String} msg
   * @param {Error} err
   */
  function formalConfigError(msg, err){
    const footer = `Please see: ${color.FgYellow}https://github.com/GeoPlatform/node-gpoauth${color.Reset}
                    for examples and information on configuration settings.`
    return new Error(`${errorHeader}\n${msg}\n${footer}\n\n${err}`)
  }

  /**
   * Log out information about a successful request.
   *
   * @param {String} status - status/message to report to use
   * @param {String} token - Token to demo to use
   * @param {Request} req - request object pull original URL from
   */
  function logRequest(status, token, req){
    debug(`${color.FgYellow}${status}${color.Reset} - Token: ${tokenDemo(token)} | ${req.method} - ${req.originalUrl}`)
  }

  // Expose ==============
  return {
    debug: debug,
    tokenDemo: tokenDemo,
    formalError: formalError,
    formalConfigError: formalConfigError,
    logRequest: logRequest
  }
}

