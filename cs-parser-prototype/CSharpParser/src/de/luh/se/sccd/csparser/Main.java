package de.luh.se.sccd.csparser;

import java.io.IOException;

import org.antlr.v4.runtime.tree.TerminalNodeImpl;

import de.luh.se.sccd.csparser.adt.DeclarationContext;
import de.luh.se.sccd.csparser.impl.SimpleCSharpParser;
import de.luh.se.sccd.csparser.impl.SimpleParseTreeWalker;

/**
 * @author Wasja Brunotte
 *
 */
public class Main
{
    
    public static void main(String[] args)
    {
        SimpleCSharpParser parser = new SimpleCSharpParser();
        
        try
        {
            parser.parse("test-src/Person.cs");
            
            parser.walk(new SimpleParseTreeWalker()
            {
                @Override
                public void enterDeclaration(DeclarationContext ctx)
                {
                    System.out.println("Enter \"" + ctx.getType() + "\" - Name: " + ctx.getName() + " - Start: " + ctx.getStartToken().getLine() + " - End: " + ctx.getEndToken().getLine());
                }
        
            }, parser.getCompilationUnit());
        }
        catch (IOException e)
        {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }
    
}
