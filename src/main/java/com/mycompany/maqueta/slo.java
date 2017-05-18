package com.mycompany.maqueta;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.Map;
import java.util.logging.Level;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.joda.time.DateTime;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutRequest;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.saml2.core.SessionIndex;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleLogoutService;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

/***
 * Este Servlet se encarga de el Single Logout invalidando la sesión.
 * Hay tres tipos de mensajes que pueden llegarle:
 * - Logout desde la maqueta (No es un Logout Request, sólo es una redirección)
 * - Logout Request desde otro SP, teóricamente habría que validar el mensaje y las credenciales,
 *   no se ha podido procesar el mensaje porque devuelve com.sun.org.apache.xerces.internal.impl.io.MalformedByteSequenceException: Byte no válido 1 de la secuencia UTF-8 de 1 bytes
 *   por lo que el Servlet no responde con un Logout Response (que requeriria el ID del Request que llegó pero no se ha podido leer el request)
 *   sino que se responder un Logout Request, a lo que el IdP toma como válido y desloguea
 * - Logout Response desde otro SP, teoricamente habría que procesarlo también para ver si el ID coincide
 *   y si la respuesta es un Success o un fail, hoy en día si recibe un response sólo lo loguea
 * @author francisco.perdomo
 */
public class slo extends HttpServlet{
    static final Logger logger = LoggerFactory.getLogger(slo.class);
    
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException{ 
        logger.info("eID logger - Entré a Servlet de Single Logout");
        imprimirJSessionID(request);
        
        String id = ""+request.getSession().getAttribute("NameID");
        Map<String, String[]> map= request.getParameterMap();
        //recorrerMensaje(map);                                     //Imprime los componentes del mensaje
        if(map.get("SAMLRequest")!=null){
            logger.info("eID logger - Me llego un SAMLRequest para Logout");
           // procesarRequest(request);
           // Debería ir un if(es la misma sesión y el mensaje y credenciales son válidas)
            request.getSession().setAttribute("Autenticado",false);     //Teóricamente no es necesario, porque luego se invalida la sesión
            request.getSession().invalidate();                          //Asegurarse no cuesta nada
            sendLogoutRequest(response,id);
        }else if (map.get("SAMLResponse")!=null){
            logger.info("eID logger - Me llegó un Response, la sesión se cerró exitosamente");
            // procesarRequest(request);
            // Debería ir un if(es la misma sesión y el response es un success)
            request.getSession().setAttribute("Autenticado",false);     //Teóricamente no es necesario, porque luego se invalida la sesión
            request.getSession().invalidate();                          //Asegurarse no cuesta nada
        }else {
            logger.info("eID logger - Logout pedido desde la maqueta");
            request.getSession().setAttribute("Autenticado",false);     //Teóricamente no es necesario, porque luego se invalida la sesión
            request.getSession().invalidate();                          //Asegurarse no cuesta nada
            sendLogoutRequest(response, id);
        }           
    }
    
   private void sendLogoutRequest(HttpServletResponse httpServletResponse, String nid) {
        LogoutRequest logoutRequest = buildLogoutRequest(nid);
        redirectUserWithRequest(httpServletResponse, logoutRequest);
    }

    private LogoutRequest buildLogoutRequest(String nid) {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        LogoutRequest logoutRequest = (LogoutRequest) builderFactory.getBuilder(LogoutRequest.DEFAULT_ELEMENT_NAME).buildObject(LogoutRequest.DEFAULT_ELEMENT_NAME);
            logoutRequest.setIssueInstant(new DateTime());
            logoutRequest.setDestination(Constantes.SLO_SERVICE);
            logoutRequest.setID(OpenSAMLUtils.generateSecureRandomId());
            logoutRequest.setIssuer(buildIssuer());
            logoutRequest.setNameID(buildNameId(nid));
        return logoutRequest;
    }    
    
    private void redirectUserWithRequest(HttpServletResponse httpServletResponse, LogoutRequest logoutRequest) {

        MessageContext context = new MessageContext();
            context.setMessage(logoutRequest);
        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
            endpointContext.setEndpoint(getIPDEndpoint());

        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

        context.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
            encoder.setMessageContext(context);
            encoder.setHttpServletResponse(httpServletResponse);
        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }
        logger.info("eID logger - LogoutRequest: ");
        OpenSAMLUtils.logSAMLObject(logoutRequest);

        logger.info("eID logger - Redirigiendo al IDP: "+Constantes.SLO_SERVICE);
        try {
            encoder.encode();
        }catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }

    // ------------------------------------------------------------------------------------------------
    private void sendLogoutResponse(HttpServletResponse httpServletResponse, String nid) {
        LogoutResponse logoutResponse = buildLogoutResponse(nid);
        redirectUserWithResponse(httpServletResponse, logoutResponse);
    }

    private LogoutResponse buildLogoutResponse(String nid) {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        LogoutResponse logoutResponse = (LogoutResponse) builderFactory.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME).buildObject(LogoutResponse.DEFAULT_ELEMENT_NAME);
            logoutResponse.setIssueInstant(new DateTime());
            logoutResponse.setDestination(Constantes.SLO_SERVICE);
            logoutResponse.setID(OpenSAMLUtils.generateSecureRandomId());
            logoutResponse.setIssuer(buildIssuer());
            logoutResponse.setInResponseTo(nid);  //nid debería ser el ID que hay en el SAMLRequest, como no puedo leerla no puedo ponerlo   
            logoutResponse.setStatus(generarStatus());
        return logoutResponse;
    }    
    
    private void redirectUserWithResponse(HttpServletResponse httpServletResponse, LogoutResponse logoutResponse) {
        MessageContext context = new MessageContext();
            context.setMessage(logoutResponse);
        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
            endpointContext.setEndpoint(getIPDEndpoint());

        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

        context.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);

        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
            encoder.setMessageContext(context);
            encoder.setHttpServletResponse(httpServletResponse);
        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }
        logger.info("eID logger - LogoutResponse: ");
        OpenSAMLUtils.logSAMLObject(logoutResponse);

        logger.info("eID logger - Redirigiendo al IDP: "+Constantes.SLO_SERVICE);
        try {
            encoder.encode();
        }catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    
    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
            issuer.setValue(Constantes.SP_ENTITY_ID);
        return issuer;
    }

    private Endpoint getIPDEndpoint() {
        SingleLogoutService endpoint = OpenSAMLUtils.buildSAMLObject(SingleLogoutService.class);
            endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            endpoint.setLocation(Constantes.SLO_SERVICE);
        return endpoint;
    }
    private NameID buildNameId(String nid) {
        NameID nameID = OpenSAMLUtils.buildSAMLObject(NameID.class);
            nameID.setFormat(NameIDType.UNSPECIFIED);
            nameID.setValue(nid); //aqui iria el subject ej: xmlns:saml2="urn:oasis:names:tc:SAML:2.0:assertion">uy-ci-42502648
        return nameID;
    }
    private Status generarStatus (){
        StatusBuilder statusBuilder = new StatusBuilder();// builderFactory.getBuilder(Status.DEFAULT_ELEMENT_NAME);
        Status status = statusBuilder.buildObject();
        StatusCodeBuilder statusCodeBuilder = new StatusCodeBuilder(); //(StatusCodeBuilder) builderFactory.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
        StatusCode statusCode = statusCodeBuilder.buildObject();
            statusCode.setValue(StatusCode.SUCCESS);
            status.setStatusCode(statusCode);
        return status;
    }
    private SessionIndex getSessionIndex(String valor){  //No utilizado, no es necesario para la validación del mensaje
        SessionIndex sessionindex = OpenSAMLUtils.buildSAMLObject(SessionIndex.class);
        sessionindex.setSessionIndex(valor);
        return sessionindex;
    }  
    private void recorrerMensaje (Map<String,String[]> map){
        for (String key : map.keySet()) {
            System.out.println(key + " " + map.get(key));
            for (String cont : map.get(key)) System.out.println(cont);
        }
    }
    private void imprimirJSessionID (HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies !=null){
            for(Cookie cookie : cookies) logger.info("eID logger - JSESSIONID: "+cookie.getValue());
        }
    }
    private void procesarRequest(HttpServletRequest request) throws IOException{
        try {
            String responseMessage = request.getParameter("SAMLRequest");
            byte[] base64DecodedResponse = Base64.decode(responseMessage);
            ByteArrayInputStream is = new ByteArrayInputStream(base64DecodedResponse);
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
                documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(is);
            Element element = document.getDocumentElement();  
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory(); //Modificado de Configuration.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory.getUnmarshaller(element);                            //Posiblemente por errores de version de OpenSAML         
            XMLObject responseXmlObj = unmarshaller.unmarshall(element); 
            Response resp = (Response) responseXmlObj;        

           // OpenSAMLUtils.logSAMLObject(responseXmlObj);                // Descomentar si quieres leer la respuesta entera y las firmas
            
            Assertion assertion = resp.getAssertions().get(0);            
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
                profileValidator.validate(assertion.getSignature());
            BasicX509Credential credential = CredencialIDP.getCredencialIDP();
            SignatureValidator.validate(assertion.getSignature(),(Credential)credential);
            
            logger.info("eID logger - Validación de credenciales exitosa");
        } catch (Base64DecodingException ex) {
            java.util.logging.Logger.getLogger(acs.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SAXException ex) {
            java.util.logging.Logger.getLogger(acs.class.getName()).log(Level.SEVERE, null, ex);
        } catch (UnmarshallingException ex) {
            java.util.logging.Logger.getLogger(acs.class.getName()).log(Level.SEVERE, null, ex);
        } catch (ParserConfigurationException ex) {
            java.util.logging.Logger.getLogger(acs.class.getName()).log(Level.SEVERE, null, ex);
        } catch (SignatureException ex) {
            java.util.logging.Logger.getLogger(acs.class.getName()).log(Level.SEVERE, null, ex);
        }
    }
}

