
import rmlparser.XMLParser;
import linkingGenerator.CWELinking;
import rmlparser.XMLParserJena;

import org.apache.commons.io.IOUtils;
import org.apache.jena.rdf.model.*;
import org.apache.jena.riot.Lang;
import org.apache.jena.riot.RDFDataMgr;
import org.apache.jena.vocabulary.RDF;
import org.eclipse.rdf4j.common.io.IOUtil;
import org.eclipse.rdf4j.model.Model;
import org.eclipse.rdf4j.rio.RDFFormat;
import org.eclipse.rdf4j.rio.Rio;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;

public class CWEXMLParser {

    public static void main(String[] args) throws Exception {

        String xmlFileName = "./input/1000.xml";
        String RMLFile = "rml/nvdcvenew-complete.rml";
        org.apache.jena.rdf.model.Model CWEModel = XMLParserJena.Parse(xmlFileName, RMLFile);  
        String fileName = xmlFileName.substring(xmlFileName.lastIndexOf("/") + 1);
        
        CWEModel.write(System.out,"TURTLE");System.exit(0);
        
        org.apache.jena.rdf.model.Model CAPECModel = ModelFactory.createDefaultModel() ;
		CAPECModel.read("output/1000-capec_o.ttl") ;
        
        org.apache.jena.rdf.model.Model testCWELinking = CWELinking.generateLinking(CWEModel, CAPECModel, fileName);
            
        //CWEModel.write( System.out,"TURTLE");
        //testCWELinking.write( System.out,"TURTLE");
        
        //call CWELingking
        String LinkingFileNameCWE = "output/linking/"+fileName+"-linkingCWETOCAPEC.ttl";
        String fileNameCWE = "output/"+fileName+".ttl";
        
        FileWriter outCWE = new FileWriter(fileNameCWE);
        FileWriter outCWELinking = new FileWriter(LinkingFileNameCWE);
        
        try {
        	CWEModel.write(outCWE,"TURTLE");
        	testCWELinking.write(outCWELinking,"TURTLE");
        	
        }
        finally {
           CWEModel.close();
		   CAPECModel.close();
        }

    }
        
       
    }


    
   


