/**
 * 
 */
package de.luh.se.sccd.csparser.adt;

import java.util.List;

import org.antlr.v4.runtime.Token;
import org.antlr.v4.runtime.tree.TerminalNodeImpl;

/**
 * This class holds information for a declaration context. See eType enum for possible declarations.
 * @author Wasja Brunotte
 *
 */
public class DeclarationContext
{
    public enum eType { Class, Constructor, Destructor, Method, Property };
    
    protected eType type;
    protected List<TerminalNodeImpl> terminals;
    protected String name;
    protected Token startToken;
    protected Token endToken;
    
    public DeclarationContext(eType type,
                           List<TerminalNodeImpl> terminals,
                           String name,
                           Token startToken,
                           Token endToken)
    {
        this.type = type;
        this.terminals = terminals;
        this.name = name;
        this.startToken = startToken;
        this.endToken = endToken;    
    }
    
    /**
     * Gets the line number where the declaration starts
     * @return start line number
     */
    public int startLine() { return this.startToken.getLine(); }
    
    
    /**
     * Gets the line number where the declaration ends
     * @return end line number
     */
    public int endLine() { return this.endToken.getLine(); }
    
    /**
     * @return the type
     */
    public eType getType()
    {
        return this.type;
    }
    /**
     * Gets the list of tokens
     * @return the terminals
     */
    public List<TerminalNodeImpl> getTerminals()
    {
        return this.terminals;
    }
    /**
     * Gets the name of the declaration context e.g. the method name
     * @return the name
     */
    public String getName()
    {
        return this.name;
    }
    /**
     * Gets the start token of the declaration
     * @return the startToken
     */
    public Token getStartToken()
    {
        return this.startToken;
    }
    /**
     * Gets the end token
     * @return the endToken
     */
    public Token getEndToken()
    {
        return this.endToken;
    }
}
