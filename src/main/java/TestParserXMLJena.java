
import rmlparser.XMLParser;
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

public class TestParserXMLJena {

    public static void main(String[] args) throws Exception {

        String xmlFileName = "./input/cveyear/nvdcve-2.0-2003.xml";
        String RMLFile = "rml/nvdcvenew-complete.rml";
        org.apache.jena.rdf.model.Model testModel = XMLParserJena.Parse(xmlFileName, RMLFile);     
         testModel.write( System.out,"TURTLE");
        String fileName = "output/cveyear/nvdcve-2.0-2003.ttl";
        FileWriter out = new FileWriter(fileName);
        try {
        	testModel.write(out,"TURTLE");
        }
        finally {
           try {
        	 
               out.close();
               
           }
           catch (IOException closeException) {
               // ignore
           }
        }

    }
        
       
    }


    
   


