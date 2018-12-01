package de.luh.se.sccd.csparser.impl;

import java.io.IOException;
import java.nio.charset.Charset;

import org.antlr.v4.runtime.CharStream;
import org.antlr.v4.runtime.CharStreams;
import org.antlr.v4.runtime.CommonTokenStream;
import org.antlr.v4.runtime.tree.ParseTreeWalker;

import de.luh.se.sccd.csparser.antlr.CSharpLexer;
import de.luh.se.sccd.csparser.antlr.CSharpParser.Compilation_unitContext;

/**
 * Prototype of a C# Language Parser
 * @author Wasja Brunotte
 *
 */
public class SimpleCSharpParser
{
    protected CommonTokenStream commonTokenStream;
    protected de.luh.se.sccd.csparser.antlr.CSharpParser csParser;
    
    /**
     * Parses a C# code file
     * @param csCodeFile path to the c# code file
     * @throws IOException
     */
    public void parse(String csCodeFile) throws IOException
    {
        CharStream charStream = CharStreams.fromFileName(csCodeFile, Charset.forName("UTF-8"));
        CSharpLexer lexer = new CSharpLexer(charStream);
        this.commonTokenStream = new CommonTokenStream(lexer);
        this.csParser = new de.luh.se.sccd.csparser.antlr.CSharpParser(commonTokenStream);
    }
    
    /**
     * returns the compilation unit of the parser
     * @return Compilation_unitContext
     */
    public Compilation_unitContext getCompilationUnit()
    {
        return this.csParser.compilation_unit();
    }
    
    /**
     * Walks through the AST of the parsed code file
     * @param walker 
     * @param cu
     */
    public void walk(SimpleParseTreeWalker walker, Compilation_unitContext cu)
    {
        ParseTreeWalker.DEFAULT.walk(walker, cu);
    }    
    
}
