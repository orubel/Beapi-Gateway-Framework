/*
 * Academic Free License ("AFL") v. 3.0
 * Copyright 2014-2017 Owen Rubel
 *
 * IO State (tm) Owen Rubel 2014
 * API Chaining (tm) Owen Rubel 2013
 *
 *   https://opensource.org/licenses/AFL-3.0
 */

package grails.api.framework;

import grails.plugin.springsecurity.rest.RestAuthenticationProvider
import grails.plugin.springsecurity.rest.authentication.RestAuthenticationEventPublisher
import grails.plugin.springsecurity.rest.token.AccessToken
import grails.plugin.springsecurity.rest.token.reader.TokenReader
import groovy.transform.CompileDynamic
import groovy.transform.CompileStatic
import groovy.util.logging.Slf4j
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.context.SecurityContextHolder
import org.springframework.security.web.authentication.AuthenticationFailureHandler
import org.springframework.security.web.authentication.AuthenticationSuccessHandler
import org.springframework.web.filter.GenericFilterBean

import org.springframework.web.context.request.RequestContextHolder as RCH

import javax.annotation.Resource
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.ServletRequest
import javax.servlet.ServletResponse
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import javax.xml.ws.Service

import grails.util.Metadata

import org.springframework.web.context.support.WebApplicationContextUtils
import org.springframework.context.ApplicationContext

//import grails.plugin.cache.GrailsCacheManager
import org.grails.plugin.cache.GrailsCacheManager
import grails.util.Holders

import javax.servlet.http.HttpSession

import groovy.json.JsonSlurperClassic
import groovy.util.logging.Slf4j
//import org.springframework.web.filter.OncePerRequestFilter
import org.springframework.web.filter.GenericFilterBean
import javax.servlet.FilterChain
import javax.servlet.ServletException
import javax.servlet.http.HttpServletRequest
import javax.servlet.http.HttpServletResponse
import net.nosegrind.apiframework.RequestMethod
import org.grails.web.servlet.mvc.GrailsWebRequest
import grails.plugin.springsecurity.SpringSecurityService
import grails.web.servlet.mvc.GrailsParameterMap

@Slf4j
//@CompileStatic
class RequestValidationFilter extends GenericFilterBean {

    String headerName

    RestAuthenticationProvider restAuthenticationProvider

    AuthenticationSuccessHandler authenticationSuccessHandler
    AuthenticationFailureHandler authenticationFailureHandler
    RestAuthenticationEventPublisher authenticationEventPublisher

    TokenReader tokenReader
    String validationEndpointUrl
    Boolean active

    Boolean enableAnonymousAccess
    GrailsCacheManager grailsCacheManager


    List optionalParams = ['method','format','contentType','encoding','action','controller','v','apiCombine', 'apiObject','entryPoint','uri']

    @Override
    void doFilter(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain) throws IOException, ServletException {
        //println("#### RequestValidationFilter ####")
        HttpServletRequest request = servletRequest as HttpServletRequest
        HttpServletResponse response = servletResponse as HttpServletResponse

        AccessToken accessToken

        try {
            accessToken = tokenReader.findToken(request)
            if (accessToken) {
                //log.debug "Token found: ${accessToken.accessToken}"

                accessToken = restAuthenticationProvider.authenticate(accessToken) as AccessToken

                if (accessToken.authenticated) {

                    //log.debug "Token authenticated. Storing the authentication result in the security context"
                    //log.debug "Authentication result: ${accessToken}"
                    SecurityContextHolder.context.setAuthentication(accessToken)

                    //authenticationEventPublisher.publishAuthenticationSuccess(accessToken)

                    processFilterChain(servletRequest, servletResponse, chain, accessToken)
                }else{
                    response.status = 401
                    response.setHeader('ERROR', 'Unauthorized Access attempted')
                    response.writer.flush()
                    return
                }
            } else {
                //log.debug "Token not found"
                return
            }
        } catch (AuthenticationException ae) {
            // NOTE: This will happen if token not found in database
            response.status = 401
            response.setHeader('ERROR', 'Authorization Attempt Failed')
            response.writer.flush()
            //authenticationEventPublisher.publishAuthenticationFailure(ae, accessToken)
            //authenticationFailureHandler.onAuthenticationFailure(httpRequest, httpResponse, ae)
            return
        }

    }

    @CompileDynamic
    private void processFilterChain(ServletRequest servletRequest, ServletResponse servletResponse, FilterChain chain, AccessToken authenticationResult) {

        HttpServletRequest request = servletRequest as HttpServletRequest
        HttpServletResponse response = servletResponse as HttpServletResponse

        // REQUEST VARS USED FOR PROCESSING
        List formats = ['XML', 'JSON']
        String format = (request?.format)?request.format.toUpperCase():'JSON'
        String mthdKey = request.method.toUpperCase()
        RequestMethod mthd= (RequestMethod) RequestMethod[mthdKey]

        boolean apiThrottle = Holders.grailsApplication.config.apiThrottle as boolean
        boolean restAlt = RequestMethod.isRestAlt(mthd.getKey())

        String actualUri = request.requestURI - request.contextPath

        if (!active) {
            return
        }

        if (authenticationResult?.accessToken) {
            if (actualUri == validationEndpointUrl) {
                //log.debug "Validation endpoint called. Generating response."
                authenticationSuccessHandler.onAuthenticationSuccess(request, response, authenticationResult)
            } else {
                String entryPoint = Metadata.current.getProperty(Metadata.APPLICATION_VERSION, String.class)
                String controller
                String action

                if (actualUri ==~ /\/.{0}[a-z]${entryPoint}\/(.*)/) {
                    List params = actualUri.split('/')
                    controller = params[2]
                    action = params[3]
                } else {

                    response.status = 401
                    response.setHeader('ERROR', 'BAD Access attempted')
                    response.writer.flush()
                    return
                }

                ApplicationContext ctx = Holders.grailsApplication.mainContext
                if(ctx) {

                    // ############## START INITIALIZE CACHE #############################
                    GrailsCacheManager grailsCacheManager = ctx.getBean("grailsCacheManager");
                    //def temp = grailsCacheManager?.getCache('ApiCache')

                    def temp = grailsCacheManager?.getCache('ApiCache')
                    List cacheNames = temp.getAllKeys() as List

                    def tempCache
                    for(it in cacheNames){
                        if (it.simpleKey.toString() == controller) {
                            tempCache = temp.get(it)
                            break
                        }
                    }

                    def cache2
                    String version
                    if (tempCache?.get()) {
                        cache2 = tempCache.get() as LinkedHashMap
                        version = cache2['cacheversion']
                        if (!cache2?."${version}"?."${action}") {
                            response.status = 401
                            response.setHeader('ERROR', 'IO State Not properly Formatted for this URI. Please contact the Administrator.')
                            response.writer.flush()
                            return
                        } else {
                            def session = RCH.currentRequestAttributes().getSession()
                            session['cache'] = cache2
                            //HttpSession session = request.getSession()
                            //session['cache'] = cache2
                        }
                    }else{
                        println("no cache found")
                    }

                    HashSet roles = cache2?."${version}"?."${action}"?.roles as HashSet

                    if (!checkAuth(roles, authenticationResult)) {
                        response.status = 401
                        response.setHeader('ERROR', 'Unauthorized Access attempted')
                        response.writer.flush()
                        return
                    } else {
                        //log.debug "Continuing the filter chain"
                    }


                    // CHECK CONTENT TYPE MATCH
                    if(!doesContentTypeMatch(request)){
                        response.status = 401
                        response.setHeader('ERROR', 'ContentType does not match Requested Format')
                        response.writer.flush()
                        return
                    }

                    GrailsWebRequest webRequest = (GrailsWebRequest) RCH.getRequestAttributes();
                    GrailsParameterMap params = webRequest.getParams()

                    if(cache2) {
                        params.apiObject = (params.apiObjectVersion) ? params.apiObjectVersion : cache2['currentStable']['value']
                        params.action = (params.action == null) ? cache2[params.apiObject]['defaultAction'] : params.action
                    }else{
                        println(" #### NO CACHE #### ")
                    }

                    // CHECK REQUEST METHOD FOR ENDPOINT
                    // NOTE: expectedMethod must be capitolized in IO State file

                    String expectedMethod = cache2[params.apiObject][params.action.toString()]['method'] as String
                    if (!checkRequestMethod(mthd,expectedMethod, restAlt)) {
                        response.status = 400
                        response.setHeader('ERROR', "Expected request method '${expectedMethod}' does not match sent method '${mthd.getKey()}'")
                        response.writer.flush()
                        return
                    }

                    LinkedHashMap receives = cache2[params.apiObject][params.action.toString()]['receives'] as LinkedHashMap
                    if (!checkURIDefinitions(params, receives, authenticationResult)) {
                        response.status = 400
                        response.setHeader('ERROR', 'Expected request variables for endpoint do not match sent variables')
                        response.writer.flush()
                        return
                    }

                }else{
                    println("no ctx found")
                }
            }
        } else {
            //println("Request does not contain any token. Letting it continue through the filter chain")
        }

        chain.doFilter(request, response)
    }


    boolean checkAuth(HashSet roles, AccessToken accessToken){
        HashSet tokenRoles = []
        accessToken.getAuthorities()*.authority.each() { tokenRoles.add(it) }

        try {
            if (roles.size()==1 && roles[0] == 'permitAll') {
                return true
            } else if(roles.intersect(tokenRoles).size()>0) {
                return true
            }
            return false
        }catch(Exception e) {
            throw new Exception("[RequestValidationFilter :: checkAuth] : Exception - full stack trace follows:",e)
        }
    }

    boolean checkRequestMethod(RequestMethod mthd,String method, boolean restAlt){
        if(!restAlt) {
            return (mthd.getKey() == method) ? true : false
        }
        return true
    }

    // TODO: put in OPTIONAL toggle in application.yml to allow for this check
    boolean checkURIDefinitions(GrailsParameterMap params,LinkedHashMap requestDefinitions, AccessToken authenticationResult){
        ArrayList reservedNames = ['batchLength','batchInc','chainInc','apiChain','_','max','offset']
        try{
            String authority = getUserRole(authenticationResult) as String
            ArrayList temp = []
            if(requestDefinitions["${authority}"]){
                temp = requestDefinitions["${authority}"] as ArrayList
            }else if(requestDefinitions['permitAll'][0]!=null){
                temp = requestDefinitions['permitAll'] as ArrayList
            }

            ArrayList requestList = (temp!=null)?temp.collect(){ it.name }:[]

            LinkedHashMap methodParams = getMethodParams(params)
            ArrayList paramsList = methodParams.keySet() as ArrayList

            // remove reservedNames from List
            reservedNames.each(){ paramsList.remove(it) }

            if (paramsList.size() == requestList.intersect(paramsList).size()) {
                return true
            }

            return false
        }catch(Exception e) {
            throw new Exception("[RequestValidationFilter :: checkURIDefinitions] : Exception - full stack trace follows:",e)
        }
        return false
    }

    String getUserRole(AccessToken authenticationResult) {
        String authority = 'permitAll'
        authority = authenticationResult.getAuthorities()*.authority[0]

        return authority
    }

    boolean doesContentTypeMatch(HttpServletRequest request){
        String format = (request?.format)?request.format.toUpperCase():'JSON'
        String contentType = request.getContentType()
        try{
            switch(contentType){
                case 'text/xml':
                case 'application/xml':
                    return 'XML'==format
                    break
                case 'text/json':
                case 'application/json':
                default:
                    return 'JSON'==format
                    break
            }
            return false
        }catch(Exception e){
            throw new Exception("[RequestValidationFilter :: getContentType] : Exception - full stack trace follows:",e)
        }
    }

    LinkedHashMap getMethodParams(GrailsParameterMap params){
        try{
            LinkedHashMap paramsRequest = [:]
            paramsRequest = params.findAll { it2 -> !optionalParams.contains(it2.key) }
            return paramsRequest
        }catch(Exception e){
            throw new Exception("[RequestValidationFilter :: getMethodParams] : Exception - full stack trace follows:",e)
        }
        return [:]
    }
}
