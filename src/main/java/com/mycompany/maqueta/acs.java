package com.mycompany.maqueta;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import javax.servlet.ServletException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import org.xml.sax.SAXException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.xml.security.exceptions.Base64DecodingException;
import org.apache.xml.security.utils.Base64;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Response;
import org.opensaml.saml.security.impl.SAMLSignatureProfileValidator;
import org.opensaml.xmlsec.signature.support.SignatureException;
import org.opensaml.xmlsec.signature.support.SignatureValidator;
import org.opensaml.security.credential.Credential;
import org.opensaml.security.x509.BasicX509Credential;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/***
 * Este Servlet recibe el Authentication Response del IdP, valida sus credenciales y setea True 
 * el parámetro Autenticado de la sesión
 * @author francisco.perdomo
 */
public class acs extends HttpServlet {
    static final Logger logger = LoggerFactory.getLogger(acs.class);
    Assertion assertionImpresion;
    
    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        try {
            String responseMessage = request.getParameter("SAMLResponse");
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
            String mensaje = OpenSAMLUtils.getSAMLObject(responseXmlObj);                // Descomentar si quieres leer la respuesta entera y las firmas
            
            Assertion assertion = resp.getAssertions().get(0);            
            SAMLSignatureProfileValidator profileValidator = new SAMLSignatureProfileValidator();
                profileValidator.validate(assertion.getSignature());
            BasicX509Credential credential = CredencialIDP.getCredencialIDP();
            SignatureValidator.validate(assertion.getSignature(),(Credential)credential);           
            logger.info("eID logger - Validación de credenciales exitosa");
            
            if (mensaje.contains("Success")){
                request.getSession().setAttribute("Autenticado",true);
                request.getSession().setAttribute("NameID", assertion.getSubject().getNameID().getValue() );
                logger.info("eID logger - El valor de Autenticado de la sesión es: "+request.getSession().getAttribute("Autenticado")); 
                imprimirJSESSIONID(request);   
                assertionImpresion = assertion;
                XMLObject att = assertionImpresion.getOrderedChildren().get(6);
                List<XMLObject> listAtt = att.getOrderedChildren();
        
                PrintWriter out = response.getWriter();
                    out.println("<!DOCTYPE html>");
                    out.println("<html>");
                    out.println("<head>");
                    out.println("<title>Assertion Consumer Service </title>");            
                    out.println("</head>");
                    out.println("<body>");
                    out.println("<h1>Firma Validada</h1>");
                    out.println("<h1>¡Enhorabuena! Usted ha realizado un SSO exitoso</h1>");
                    out.println("<h2>Datos ingresados</>");
                    out.println("<p>Nombre: "+listAtt.get(3).getDOM().getTextContent());
                    out.println("<p>Subject: "  + assertionImpresion.getSubject().getNameID().getValue());
                    out.println("<p>Issuer: "   + assertionImpresion.getIssuer().getValue());
                    out.println("<p>Audience: " + assertionImpresion.getConditions().getAudienceRestrictions().get(0).getAudiences().get(0).getAudienceURI());
                    out.println("<p>Certificado: "+listAtt.get(0).getDOM().getTextContent());  
                    out.println("<p>Firmado con: "+assertionImpresion.getOrderedChildren().get(5).getOrderedChildren().get(1).getDOM().getTextContent());
                    out.println("<p><a href=\"slo\" class=\"button\"> SLO </button> </br>");
                    out.println("</body>");
                    out.println("</html>");
            }
            else{
                PrintWriter out = response.getWriter();
                    out.println("<!DOCTYPE html>");
                    out.println("<html>");
                    out.println("<head>");
                    out.println("<title>Assertion Consumer Service </title>");            
                    out.println("</head>");
                    out.println("<body>");
                    out.println("<h1>El request fue negado</h1>");
                    out.println("<p><a href=\"SSO_FULL\" class=\"button\"> Volver </button> </br>");
                    out.println("</body>");
                    out.println("</html>");
            }
            	
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
    private void imprimirJSESSIONID (HttpServletRequest request){
        Cookie[] cookies = request.getCookies();
        if(cookies !=null){
            for(Cookie cookie : cookies) logger.info("eID logger - JSESSIONID: "+cookie.getValue());
        }
    }
}