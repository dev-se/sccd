package de.luh.se.sccd.csparser.impl;

import java.util.ArrayList;

import org.antlr.v4.runtime.RuleContext;
import org.antlr.v4.runtime.tree.ParseTree;
import org.antlr.v4.runtime.tree.TerminalNodeImpl;

import de.luh.se.sccd.csparser.adt.DeclarationContext;
import de.luh.se.sccd.csparser.antlr.CSharpParser;
import de.luh.se.sccd.csparser.antlr.CSharpParserBaseListener;

/**
 * Prototype of a Simple Parse Tree Walker class
 * Only the enterDeclaration should be overwritten for a parser. The DeclarationContext parameter holds all the information
 * @author Wasja Brunotte
 *
 */
public class SimpleParseTreeWalker extends CSharpParserBaseListener
{
    public void enterDeclaration(DeclarationContext ctx) { }
    
    @Override
    public void enterClass_definition(CSharpParser.Class_definitionContext ctx)
    {
        if (ctx.identifier() != null)
            enterDeclaration(new DeclarationContext(DeclarationContext.eType.Class,
                                              new ArrayList<>(),
                                              ctx.identifier().getText(),
                                              ctx.getStart(),
                                              ctx.getStop()));    
    }
    
    @Override
    public void enterConstructor_declaration(CSharpParser.Constructor_declarationContext ctx)
    {
        String name = "";
        ArrayList<TerminalNodeImpl> terminals = new ArrayList<TerminalNodeImpl>();
        
        if (ctx.identifier() != null)
            name = ctx.identifier().getText();
                
        if (ctx.body() != null)
            this.extractTokensFromRuleContext(ctx.getPayload(), terminals);
        
        enterDeclaration(new DeclarationContext(DeclarationContext.eType.Constructor,
                                          terminals,
                                          name,
                                          ctx.getStart(),
                                          ctx.getStop()));
    }
    
    @Override
    public void enterDestructor_definition(CSharpParser.Destructor_definitionContext ctx)
    {
        String name = "";
        ArrayList<TerminalNodeImpl> terminals = new ArrayList<TerminalNodeImpl>();
        
        if (ctx.identifier() != null)
            name = ctx.identifier().getText();
                
        if (ctx.body() != null)
            this.extractTokensFromRuleContext(ctx.getPayload(), terminals);
        
        enterDeclaration(new DeclarationContext(DeclarationContext.eType.Destructor,
                                          terminals,
                                          name,
                                          ctx.getStart(),
                                          ctx.getStop()));
    }
    
    @Override public void enterMethod_declaration(CSharpParser.Method_declarationContext ctx)
    {
        String name = "";
        ArrayList<TerminalNodeImpl> terminals = new ArrayList<TerminalNodeImpl>();
        
        if (ctx.method_member_name() != null)
            name = ctx.method_member_name().getText();
        
        // get all the tokens
        this.extractTokensFromRuleContext(ctx.getPayload(), terminals);
        
        enterDeclaration(new DeclarationContext(DeclarationContext.eType.Method,
                                          terminals,
                                          name,
                                          ctx.getStart(),
                                          ctx.getStop()));
    }
    
    @Override
    public void enterProperty_declaration(CSharpParser.Property_declarationContext ctx)
    {
        String name = "";
        ArrayList<TerminalNodeImpl> terminals = new ArrayList<TerminalNodeImpl>();
        
        if (ctx.member_name() != null)
            name = ctx.member_name().getText();
                
        this.extractTokensFromRuleContext(ctx.getPayload(), terminals);
        
        enterDeclaration(new DeclarationContext(DeclarationContext.eType.Property,
                                          terminals,
                                          name,
                                          ctx.getStart(),
                                          ctx.getStop()));
    }
    
    protected void extractTokensFromRuleContext(RuleContext ctx, ArrayList<TerminalNodeImpl> terminals)
    {
        if (ctx == null)
            return;
        
        for (int i = 0; i < ctx.getChildCount(); i++)
            this.extractTokens(ctx.getChild(i), terminals);
    }
    
    protected void extractTokens(ParseTree tree, ArrayList<TerminalNodeImpl> terminals)
    {
        if (tree == null)
            return;
        else if (tree instanceof TerminalNodeImpl)
            terminals.add((TerminalNodeImpl)tree);
        else
        {            
            for (int i = 0; i < tree.getChildCount(); i++)
                this.extractTokens(tree.getChild(i), terminals);
        }
    }
}
