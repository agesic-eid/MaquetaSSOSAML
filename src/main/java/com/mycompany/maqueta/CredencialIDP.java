package com.mycompany.maqueta;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.InputStream;

import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.logging.Level;
import org.opensaml.security.credential.CredentialSupport;
import org.opensaml.security.x509.BasicX509Credential;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredencialIDP {
    private static Logger logger = LoggerFactory.getLogger(CredencialIDP.class);
    
    public static BasicX509Credential getCredencialIDP(){
        logger.info("eID logger - Leyendo Credenciales del IDP");
        try {
            InputStream in = new FileInputStream("/Agesic-Coesys-Testing.cer");
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            X509Certificate cert = (X509Certificate) factory.generateCertificate(in);
            BasicX509Credential credential = CredentialSupport.getSimpleCredential(cert,null);           
            return credential;     
        }catch (FileNotFoundException ex) {
            java.util.logging.Logger.getLogger(acs.class.getName()).log(Level.SEVERE, null, ex);
        } catch (CertificateException ex) {
            java.util.logging.Logger.getLogger(acs.class.getName()).log(Level.SEVERE, null, ex);          
        }
        return null;
    }
}