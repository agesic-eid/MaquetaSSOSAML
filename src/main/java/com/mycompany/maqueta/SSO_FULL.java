package com.mycompany.maqueta;

import java.io.IOException;
import java.security.Provider;
import java.security.Security;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import net.shibboleth.utilities.java.support.component.ComponentInitializationException;
import org.joda.time.DateTime;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.xml.XMLObjectBuilderFactory;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.messaging.context.MessageContext;
import org.opensaml.messaging.encoder.MessageEncodingException;
import org.opensaml.saml.common.messaging.context.SAMLEndpointContext;
import org.opensaml.saml.common.messaging.context.SAMLPeerEntityContext;
import org.opensaml.saml.common.xml.SAMLConstants;
import org.opensaml.saml.saml2.binding.encoding.impl.HTTPRedirectDeflateEncoder;
import org.opensaml.saml.saml2.core.AuthnContext;
import org.opensaml.saml.saml2.core.AuthnContextClassRef;
import org.opensaml.saml.saml2.core.AuthnContextComparisonTypeEnumeration;
import org.opensaml.saml.saml2.core.AuthnRequest;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameIDPolicy;
import org.opensaml.saml.saml2.core.NameIDType;
import org.opensaml.saml.saml2.core.RequestedAuthnContext;
import org.opensaml.saml.saml2.metadata.Endpoint;
import org.opensaml.saml.saml2.metadata.SingleSignOnService;
import org.opensaml.xmlsec.SignatureSigningParameters;
import org.opensaml.xmlsec.config.JavaCryptoValidationInitializer;
import org.opensaml.xmlsec.context.SecurityParametersContext;
import org.opensaml.xmlsec.signature.support.SignatureConstants;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/***
 * Este Servlet inicia el Single Sign On creando un Authentication Request y enviándolo al IdP
 * La sesión tiene un atributo Autenticado que sale False desde este Servlet que será pasado a True 
 * cuando se reciba un Authentication Response validando la conexión.
 * @author francisco.perdomo
 */
public class SSO_FULL extends HttpServlet {
   
    private static Logger logger = LoggerFactory.getLogger(SSO_FULL.class);
    
    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        doPost(request,response);
    }
 
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        JavaCryptoValidationInitializer javaCryptoValidationInitializer = new JavaCryptoValidationInitializer();
        try {
            javaCryptoValidationInitializer.init();
            } catch (InitializationException e) {
            e.printStackTrace();
        }
        for (Provider jceProvider : Security.getProviders()) {
            logger.info(jceProvider.getInfo());
        }

        try {
            logger.info("eID logger - Inicializan");
            InitializationService.initialize();
            } catch (InitializationException e) {
            throw new RuntimeException("eID logger - Initialization failed");
        }
        request.getSession().setAttribute("Autenticado", false);     
        logger.info("eID logger - El valor de Autenticado de la sesión es: "+request.getSession().getAttribute("Autenticado")); 
        imprimirJSESSIONID(request);
        redirectUserForAuthentication(response);
    }

    private void redirectUserForAuthentication(HttpServletResponse httpServletResponse) {
        AuthnRequest authnRequest = buildAuthnRequest();
        redirectUserWithRequest(httpServletResponse, authnRequest);
    }

    private AuthnRequest buildAuthnRequest() {
        XMLObjectBuilderFactory builderFactory = XMLObjectProviderRegistrySupport.getBuilderFactory();
        //AuthnRequest authnRequest = OpenSAMLUtils.buildSAMLObject(AuthnRequest.class); //Hay que forzar la creación o no funciona, a corregir a futuro
        AuthnRequest authnRequest = (AuthnRequest) builderFactory.getBuilder(AuthnRequest.DEFAULT_ELEMENT_NAME).buildObject(AuthnRequest.DEFAULT_ELEMENT_NAME);
            authnRequest.setIssueInstant(new DateTime());
            authnRequest.setDestination(Constantes.SSO_SERVICE);
            authnRequest.setProtocolBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            authnRequest.setAssertionConsumerServiceURL(Constantes.ASSERTION_CONSUMER_SERVICE);
            authnRequest.setID(OpenSAMLUtils.generateSecureRandomId());
            authnRequest.setIssuer(buildIssuer());
            authnRequest.setNameIDPolicy(buildNameIdPolicy());
            authnRequest.setRequestedAuthnContext(buildRequestedAuthnContext());

        return authnRequest;
    }
    
     private void redirectUserWithRequest(HttpServletResponse httpServletResponse, AuthnRequest authnRequest) {

        SignatureSigningParameters signatureSigningParameters = new SignatureSigningParameters();
            signatureSigningParameters.setSigningCredential(SPCredentials.getCredential());
            signatureSigningParameters.setSignatureAlgorithm(SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA256);

        MessageContext context = new MessageContext();
            context.setMessage(authnRequest);
            context.getSubcontext(SecurityParametersContext.class, true).setSignatureSigningParameters(signatureSigningParameters);
        
        SAMLPeerEntityContext peerEntityContext = context.getSubcontext(SAMLPeerEntityContext.class, true);
        SAMLEndpointContext endpointContext = peerEntityContext.getSubcontext(SAMLEndpointContext.class, true);
            endpointContext.setEndpoint(getIPDEndpoint());
            
        HTTPRedirectDeflateEncoder encoder = new HTTPRedirectDeflateEncoder();
            encoder.setMessageContext(context);
            encoder.setHttpServletResponse(httpServletResponse);
        try {
            encoder.initialize();
        } catch (ComponentInitializationException e) {
            throw new RuntimeException(e);
        }
        logger.info("eID logger - AuthnRequest: \n");
        OpenSAMLUtils.logSAMLObject(authnRequest);

        logger.info("eID logger - Redirigiendo al IDP: "+Constantes.SSO_SERVICE);
        try {
            encoder.encode();
        }catch (MessageEncodingException e) {
            throw new RuntimeException(e);
        }
    }
    
    private RequestedAuthnContext buildRequestedAuthnContext() {
        AuthnContextClassRef passwordAuthnContextClassRef = OpenSAMLUtils.buildSAMLObject(AuthnContextClassRef.class);
            passwordAuthnContextClassRef.setAuthnContextClassRef(AuthnContext.PASSWORD_AUTHN_CTX);
        
        RequestedAuthnContext requestedAuthnContext = OpenSAMLUtils.buildSAMLObject(RequestedAuthnContext.class);
            requestedAuthnContext.setComparison(AuthnContextComparisonTypeEnumeration.MINIMUM);     
            requestedAuthnContext.getAuthnContextClassRefs().add(passwordAuthnContextClassRef);
            
        return requestedAuthnContext;
    }
    
    private NameIDPolicy buildNameIdPolicy() {
        NameIDPolicy nameIDPolicy = OpenSAMLUtils.buildSAMLObject(NameIDPolicy.class);
            nameIDPolicy.setAllowCreate(true);
            nameIDPolicy.setFormat(NameIDType.UNSPECIFIED);
        return nameIDPolicy;
    }

    private Issuer buildIssuer() {
        Issuer issuer = OpenSAMLUtils.buildSAMLObject(Issuer.class);
            issuer.setValue(Constantes.SP_ENTITY_ID);
        return issuer;
    }

    private Endpoint getIPDEndpoint() {
        SingleSignOnService endpoint = OpenSAMLUtils.buildSAMLObject(SingleSignOnService.class);
            endpoint.setBinding(SAMLConstants.SAML2_REDIRECT_BINDING_URI);
            endpoint.setLocation(Constantes.SSO_SERVICE);
        return endpoint;
    }
    
     private void imprimirJSESSIONID (HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies !=null){
            for(Cookie cookie : cookies) logger.info("eID logger - JSESSIONID: "+cookie.getValue());
        }
    }   
}