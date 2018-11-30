package de.luh.se.sccd.plugin.evaluation;

/**
 *
 * This file contains all the vulnerable code fragments as type-2 clones
 *
 */

public class SCCDetectorEvaluator_Type_2_Clones
{
    // CVE-2017-9096 - Score: 6.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-9096
    // vulnerable code fragment
    public void fillXfaForm(InputSource is) throws ParserConfigurationException, SAXException, IOException
    {
        DocumentBuilderFactory a = DocumentBuilderFactory.newInstance();
        DocumentBuilder b = a.newDocumentBuilder();
        Document c = b.parse(is);
        fillXfaForm(c.getDocumentElement());
        
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2006-2806 - Score: 7.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2006-2806
    // vulnerable code fragment
    /**
     * @see org.apache.james.smtpserver.SMTPSession#readCommandLine()
     */
    public final String readCommandLine() throws IOException
    {
        for (;;)
            try
            {
                String cmdLine = inReader.readLine();
                if (cmdLine != null)
                {
                    cmdLine = cmdLine.trim(); // some comment
                }
                return cmdLine;
            }
            catch (CRLFTerminatedReader.TerminationException e)
            {
                writeLoggedFlushedResponse("501 Syntax error at character position " + e.position()
                        + ". CR and LF must be CRLF paired.  See RFC 2821 #2.7.1.");
            }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-1591 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-1591
    // vulnerable code fragment
    public static String randomString(int length)
    {
        if (length < 1)
        {
            // another comment
            return null;
        }
        // new comment added here
        char[] rndBuf = new char[length];
        for (int i = 0; i < rndBuf.length; i++)
        {
            rndBuf[i] = numbersAndLetters[randGen.nextInt(71)];
        }
        return new String(rndBuf);
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-1217 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-1217
    // vulnerable code fragment
    @Override
    public String getPath(Distribution distribution)
    {
        String strVersion = getVersionPart(distribution.getVersion());
        
        ArchiveType archType = getArchiveType(distribution);
        String strArchiveType;
        switch (archType)
        {
            case TGZ:
                strArchiveType = "tar.gz";
                break;
            case ZIP:
                strArchiveType = "zip";
                break;
            default:
                throw new IllegalArgumentException("Unknown ArchiveType " + archType);
        }
        
        String platformName;
        switch (distribution.getPlatform())
        {
            case Linux:
                platformName = "linux";
                break;
            case Windows:
                platformName = "windows";
                break;
            case OS_X:
                platformName = "osx";
                break;
            default:
                throw new IllegalArgumentException("Unknown Platform " + distribution.getPlatform());
        }
        
        String platformBits = "";
        switch (distribution.getBitsize())
        {
            case B32:
                switch (distribution.getPlatform())
                {
                    case Windows:
                    case Linux:
                    case OS_X:
                        break;
                    default:
                        throw new IllegalArgumentException(
                                "32 bit supported only on Windows, MacOS, Linux, platform is "
                                        + distribution.getPlatform());
                }
                break;
            case B64:
                switch (distribution.getPlatform())
                {
                    case Linux:
                    case Windows:
                        platformBits = "-x64";
                        break;
                    case OS_X:
                        break;
                    default:
                        throw new IllegalArgumentException("64 bit supported only on Linux and Windows, platform is "
                                + distribution.getPlatform());
                }
                break;
            default:
                throw new IllegalArgumentException("Unknown BitSize " + distribution.getBitsize());
        }
        
        // local variables are all renamed
        return "postgresql-" + strVersion + "-" + platformName + platformBits + "-binaries" + "." + strArchiveType;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2007-5461 - Score: 3.5/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2007-5461
    // vulnerable code fragment
    /**
     * Return JAXP document builder instance.
     */
    protected DocumentBuilder getDocumentBuilder() throws ServletException
    {
        DocumentBuilder docB = null;
        DocumentBuilderFactory docFactory = null;
        try
        {
            docFactory = DocumentBuilderFactory.newInstance();            
            docFactory.setNamespaceAware(true); // here goes a new comment 4589734957359735987
            docB = docFactory.newDocumentBuilder();
        }
        catch (ParserConfigurationException e)
        {
            throw new ServletException(sm.getString("webdavservlet.jaxpfailed"));
        }
        return docB;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2007-6203 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2007-6203
    // vulnerable code fragment
    public Cookie(String a, String b)
    {
        // comments removed and indentions changed
    	if (!isToken(a)
    		|| a.equalsIgnoreCase("Comment")
    		|| a.equalsIgnoreCase("Discard")
    		|| a.equalsIgnoreCase("Domain")
    		|| a.equalsIgnoreCase("Expires")
    		|| a.equalsIgnoreCase("Max-Age")
    		|| a.equalsIgnoreCase("Path")
    		|| a.equalsIgnoreCase("Secure")
    		|| a.equalsIgnoreCase("Version")
    		|| a.startsWith("$")
    	    )
        {
    	       String theErrorMessage = lStrings.getString("literal changed!");
    	    Object[] errorArgs = new Object[1];
            // some
            // things
            // to
            // remember
    	           errorArgs[0] = a;
    	    theErrorMessage = MessageFormat.format(theErrorMessage, errorArgs);
    	       throw new IllegalArgumentException(theErrorMessage);
	    }

	   this.a = a;
	   this.b = b;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2008-2086 - Score: 9.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2008-2086
    // vulnerable code fragment
    /*
     * this version is called from doPrivileged in privilegedOpenProfile. the whole
     * method is privileged!
     */
    private static FileInputStream privilegedOpenProfile(String fileName)
    {
        FileInputStream finstream = null;
        String pfad, directoryVar, fp;
        
        File x = new File(fileName); /* try absolute file name */
        
        if ((!x.isFile()) && ((pfad = System.getProperty("java.iccprofile.path")) != null))
        {
            /* try relative to java.iccprofile.path */
            StringTokenizer tokenizer = new StringTokenizer(pfad, File.pathSeparator);
            while (tokenizer.hasMoreTokens() && (!x.isFile()))
            {
                directoryVar = tokenizer.nextToken();

                fp = directoryVar + File.separatorChar + fileName;

                x = new File(fp);
            }
        }
        
        if ((!x.isFile()) && ((pfad = System.getProperty("java.class.path")) != null))
        {
            // removed comment and new indention
                StringTokenizer tok = new StringTokenizer(pfad, File.pathSeparator);
                while (tok.hasMoreTokens() && (!x.isFile()))
                {
                    directoryVar = tok.nextToken();
                    fp = directoryVar + File.separatorChar + fileName;
                    x = new File(fp);
                }
        }
        

                    if (!x.isFile())
                    { /* try the directory of built-in profiles */
                        directoryVar = System.getProperty("java.home") + File.separatorChar + "lib" + File.separatorChar + "cmm";
                        fp = directoryVar + File.separatorChar + fileName;
                        x = new File(fp);
                    }
        
        if (x.isFile())
        {
            try
            {
                finstream = new FileInputStream(x);
            }
            catch (FileNotFoundException e)
            {
            }
        }
        return finstream;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2008-5515 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2008-5515
    // vulnerable code fragment
    public RequestDispatcher getRequestDispatcher(String path)
    {
        
        if (ctx == null)
            return (null);
        if (path == null) // If the path is already context-relative, just pass it through
            return (null);
        else if (path.startsWith("/"))
            return (ctx.getServletContext().getRequestDispatcher(path));
        
        
        String strPath = (String) getAttribute(Globals.INCLUDE_SERVLET_PATH_ATTR); // Convert a request-relative path to a context-relative one
        if (strPath == null)
            strPath = getServletPath();
        
        // Add the path info, if there is any
        String pi = getPathInfo();
        String pathRequest = null;
        
        if (pi == null)
        {
            pathRequest = strPath;
        }
        else
        {
            pathRequest = strPath + pi;
        }
        
        int position = pathRequest.lastIndexOf('/');
        String relative = null;

        if (position >= 0)
        {
            // comment here
                relative = RequestUtil.normalize(pathRequest.substring(0, position + 1) + path);
        }
        else
        {
                    relative = RequestUtil.normalize(pathRequest + path);
        }
        
        return (ctx.getServletContext().getRequestDispatcher(relative));
        
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-0846 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-0846
    // vulnerable code fragment
    private boolean isDeviceLocked()
    {
        boolean locked = false;
        KeyguardManager kgMan = (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        boolean b = kgMan.inKeyguardRestrictedInputMode();
        if (b)
        {
            locked = true; // now it is locked
        }
        else
        {
            PowerManager powerManager = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
            //
            //
            //
            //
            //
            //
            locked = !powerManager.isScreenOn();
        }
        return locked;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-0389 - Score: 7.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-0389
    // vulnerable code fragment
    public static DhcpPacket decodeFullPacket(byte[] packet, int length, int pktType) throws ParseException
    {
            ByteBuffer buf = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN);
            // with an new comment inside
                        return decodeFullPacket(buf, pktType);
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2009-2693 - Score: 5.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2693
    // vulnerable code fragment
    public static void unjar(InputStream in, File dest) throws IOException
    {
        if (!dest.exists())
        {
            dest.mkdirs();
        }

        if (!dest.isDirectory())
        {
            throw new IOException("Destination must be a directory."); // throw exception
        }
        
        JarInputStream jarInStream = new JarInputStream(in);
        byte[] buf = new byte[1024];
        
        ZipEntry ze = jarInStream.getNextEntry();
        while (ze != null)
        {
            String fn = ze.getName();
            if (fn.charAt(fn.length() - 1) == '/')
            {
                fn = fn.substring(0, fn.length() - 1);
            }
            if (fn.charAt(0) == '/')
            {
                fn = fn.substring(1);
            }
            if (File.separatorChar != '/')
            {
                fn = fn.replace('/', File.separatorChar);
            }
            File datei = new File(dest, fn);
            if (ze.isDirectory())
            {
                // make sure the directory exists
                datei.mkdirs();
                jarInStream.closeEntry();
            }
            else
            {
                // make sure the directory exists
                File fParent = datei.getParentFile();
                if (fParent != null && !fParent.exists())
                {
                    fParent.mkdirs();
                }
                
                // dump the datei
                OutputStream ostream = new FileOutputStream(datei);
                int l = 0;
                while ((l = jarInStream.read(buf, 0, buf.length)) != -1)
                {
                    ostream.write(buf, 0, l);
                }
                ostream.flush();
                ostream.close();
                jarInStream.closeEntry();
                datei.setLastModified(ze.getTime());
            }
            ze = jarInStream.getNextEntry();
        }
        /*
         * Explicity write out the META-INF/MANIFEST.MF so that any headers such as the
         * Class-Path are see for the unpackaged jar
         */
        Manifest m = jarInStream.getManifest();
        if (m != null)
        {
            File f = new File(dest, "META-INF/MANIFEST.MF");
            File p = f.getParentFile();
            if (p.exists() == false)
            {
                p.mkdirs();
            }
            OutputStream out = new FileOutputStream(f);
            m.write(out);
            out.flush();
            out.close();
        }
        jarInStream.close();
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2009-2901 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2901
    // vulnerable code fragment
    public void setWorkDir(File wd)
    {
        // this is a very short fragment
        // CVE-2009-2901 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2901
    // vulnerable code fragment
                        this.loaderDir = new File(wd, "loader");
        // CVE-2009-2901 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2901
    // vulnerable code fragment
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2016-6723 - Score: 5.4/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2016-6723
    // vulnerable code fragment
    private static String get(Uri pacUri) throws IOException
    {
        URL x = new URL(pacUri.toString()); // get url
        URLConnection conn = x.openConnection(java.net.Proxy.NO_PROXY); // open connection
        // return the string
        return new String(Streams.readFully(conn.getInputStream()));
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2010-4172 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2010-4172
    // vulnerable code fragment
    private static String localeToString(Locale locale)
    {
        if (locale != null)
        {
            // comment removed here
            return locale.toString();
        }
        else { return ""; /* and a comment */ }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2016-3897 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2016-3897
    // vulnerable code fragment
    @Override
    public String toString()
    {
        StringBuffer strBuffer = new StringBuffer();
        
        for (String a : mFields.keySet())
        {
                        strBuffer.append(a).append(" ").append(mFields.get(a)).append("\n");
        }


        return strBuffer.toString();
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2011-1475 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2011-1475
    // vulnerable code fragment
    @Override
    public void log(org.apache.coyote.Request req, org.apache.coyote.Response res, long time)
    {
        
        Request anfrage = (Request) req.getNote(ADAPTER_NOTES);
        Response antwort = (Response) res.getNote(ADAPTER_NOTES);
        boolean b = false;
        
        if (anfrage == null)
        {
            b = true;
            

            anfrage = connector.createRequest(); // create all the objects
            anfrage.setCoyoteRequest(req);
            antwort = connector.createResponse();
            antwort.setCoyoteResponse(res);
            
                    anfrage.setResponse(antwort); // link object
                    antwort.setRequest(anfrage);
            

            req.setNote(ADAPTER_NOTES, anfrage); // "set as notes" comment
            res.setNote(ADAPTER_NOTES, antwort);
            
            req.getParameters().setQueryStringEncoding(connector.getURIEncoding());
            // abc
        }
        
        connector.getService().getContainer().logAccess(anfrage, antwort, time, true);
        
        if (b)
        {
            anfrage.recycle();
            antwort.recycle();
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2011-3190 - Score: 7.5/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2011-3190
    // vulnerable code fragment
    /**
     * Finish AJP response.
     */
    protected void finish() throws IOException
    {
        
            if (!response.isCommitted())
        {
            try { prepareResponse(); }
            catch (IOException q) { /* inline comment */ error = true; }
        }
        
        if (finished)
        // with comment 
        return;
        
        finished = true;
        
        // Add the end message
        if (error) {
            output(endAndCloseMessageArray, 0, endAndCloseMessageArray.length); }
        else   {            output(endMessageArray, 0, endMessageArray.length);        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2011-3377 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2011-3377
    // vulnerable code fragment
    /**
     * Throws a SecurityException if the permission is denied, otherwise return
     * normally. This method always denies permission to change the security manager
     * or policy.
     */
    public void checkPermission(Permission paramPermission)
    {
        String nameOfPermission = paramPermission.getName();
        
        if (!JNLPRuntime.isWebstartApplication() && ("setPolicy".equals(nameOfPermission) || "setSecurityManager".equals(nameOfPermission)))
            throw new SecurityException(R("RCantReplaceSM")); // short comment
        
        try
        {
            try { super.checkPermission(paramPermission); }
            
            catch (SecurityException se)
            {
                
                if (JNLPRuntime.isDebug())
                    System.err.println("Requesting permission: " + paramPermission.toString());
                    
                Permission tmp = null;

                // all commens removed

                if (paramPermission instanceof SocketPermission)
                {
                    tmp = new SocketPermission(paramPermission.getName(), SecurityConstants.SOCKET_CONNECT_ACCEPT_ACTION);
                    
                    // before proceeding, check if we are trying to connect to same origin
                    ApplicationInstance a = getApplication();
                    JNLPFile file = a.getJNLPFile();
                    
                    String src = file.getSourceLocation().getAuthority();
                    String dst = nameOfPermission;
                    
                    
                    if (dst.indexOf(':') >= 0)
                        dst = dst.substring(0, dst.indexOf(':')); // comment
                    
                    String[] arrayData = dst.split("\\.");
                    
                    int size = arrayData.length;
                    
                    if (size >= 2)
                    {
                        
                        dst = arrayData[size - 2] + "." + arrayData[size - 1]; // format check
                        
                        boolean trueOrFalse = false; // yes or no
                        
                        try {                            Integer.parseInt(arrayData[size - 1]);                        }
                        catch (NumberFormatException e)                        {                            trueOrFalse = true;                        }
                        
                        if (trueOrFalse)
                        {
                            if (src.endsWith(dst))                            {                                addPermission(tmp);                                return;
                            }
                        }
                    }
                }
                else                {                    tmp = paramPermission;                }
                
                if (tmp != null)
                {
                    if (askPermission(tmp))                    {                        addPermission(tmp);
                    }
                    else                    {                        throw se;                    } // throw
                }
            }
        }
        catch (SecurityException ex)
        {
            if (JNLPRuntime.isDebug())            {                System.out.println("Denying permission: " + paramPermission);            }
            throw ex;
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2012-1621 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2012-1621
    // vulnerable code fragment
    public static void readOperations(Element param1, List<MethodOperation> param2,
            SimpleMethod param3)
    {
        List<? extends Element> opElems = UtilXml.childElementList(param1);
        
        if (UtilValidate.isNotEmpty(opElems))
        {
            for (Element e : opElems)
            {
                String nameOfNode = e.getNodeName();
                
                MethodOperation x = null;
                
                MethodOperation.Factory<MethodOperation> factory = methodOperationFactories.get(nameOfNode);
                
                


                if (factory != null)
                {
                    x = factory.createMethodOperation(e, param3);
                }
                else if ("else".equals(nameOfNode)) { } // comment removed and one line now
                
                else
                {
                    Debug.logWarning("Operation element \"" + nameOfNode + "\" no recognized", module);
                }
                



                if (x == null)
                    continue;
                




                if (UtilProperties.propertyValueEquals("webslinger-invoker.properties", "wrap-calls", "true"))
                {
                    Wrap<MethodOperation> z = new Wrap<MethodOperation>().fileName(param3.getLocationAndName())
                            .wrappedClass(x.getClass());
                    z.wrap(methodOperationExecMethod);
                    Object sl = e.getUserData("startLine");
                    if (sl != null)
                    {
                        z.lineNumber(((Integer) sl).intValue());
                    }
                    x = z.newInstance(new Class<?>[] { Element.class, SimpleMethod.class },
                            new Object[] { e, param3 });
                }
                
            param2.add(x);
                        DeprecatedOperation depOp = x.getClass().getAnnotation(DeprecatedOperation.class);
                        if (depOp != null)
                            Debug.logInfo("The " + nameOfNode + " operation has been deprecated in favor of the " + depOp.value()
                                    + " operation; found use of this in [" + param3.getShortDescription() + "]: "
                                    + x.rawString(), module);
            }
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2012-2459 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2012-2459
    // vulnerable code fragment
    private Node build(List<Node> n)
    {
        if (n.isEmpty()) { return new Node(Bytes.EMPTY_HASH); }
        
        while (n.size() > 1)
        {
            List<Node> genericVar = new ArrayList<>();
            
            if (n.size() % 2 != 0)            {                                n.add(new Node(n.get(n.size() - 1).value));
            }
            
            for (int j = 0; j < n.size() - 1; j += 2)
            {
                Node l = n.get(j);
                Node r = n.get(j + 1);
                genericVar.add(new Node(Hash.h256(l.value, r.value), l, r));
            }

            // comment added 
            // comment added
            // comment added
            // comment added
            // comment added
            
            levels++;
            n = genericVar;
        }
        
                levels++;
        return n.get(0);
    }

    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
 // non vulenrable code fragments from Security Code Clone Detector Plugin
    public static void openFile(IFile file, int gotoLineNumber, final StatusReporter statusReporter)
    {
        try
        {
            IWorkbenchPage page = PlatformUI.getWorkbench().getActiveWorkbenchWindow().getActivePage();
            org.eclipse.ui.IEditorPart editor = IDE.openEditor(page, file);            
            
            if (editor instanceof ITextEditor)
            {
                ITextEditor txtEditor = (ITextEditor)editor;
                
                org.eclipse.ui.texteditor.IDocumentProvider docProvider = txtEditor.getDocumentProvider();
                IDocument document = docProvider.getDocument(editor.getEditorInput());
                
                int startOffset = gotoLineNumber == -1 ? -1 : document.getLineOffset(gotoLineNumber - 1);
                
                // selects whole line
                if (gotoLineNumber > -1)
                    txtEditor.selectAndReveal(startOffset, document.getLineLength(gotoLineNumber - 1));
                
                // goto line without selection
                //if (gotoLineNumber > -1)
                    // txtEditor.selectAndReveal(startOffset, 0);
            }
        }
        catch (Exception e)
        {
            if (statusReporter != null)
            {
                Status status =  new Status(IStatus.ERROR, de.luh.se.sccd.plugin.Activator.PLUGIN_ID, "EclipseFileUtil.OpenFile", e);
                statusReporter.report(status, StatusReporter.LOG);            
            }
            e.printStackTrace();
        }
    }
    
    public boolean HasChanged(IFile file, long newFileSize)
    {
        long cachedSize = this.getFileSize(file);
        
        if (cachedSize == 0)
            return cachedSize != newFileSize;
        
        long diff = Math.max(cachedSize, newFileSize) - Math.min(cachedSize, newFileSize);
        
        return diff >= this.minimumBytesChanged;        
    }
    
    @Override
    public void resourceChanged(IResourceChangeEvent event)
    {
        // we are only in resource changes interested like file save operations
        if (event.getType() != IResourceChangeEvent.POST_CHANGE && event.getDelta().getKind() != IResourceDelta.CHANGED)
            return;
        
        try
        {
            event.getDelta().accept(new IResourceDeltaVisitor()
                    {
                        public boolean visit(IResourceDelta delta)
                        {
                            // only interested in changed resources and content changes
                            if (delta.getKind() != IResourceDelta.CHANGED)// && ((delta.getFlags() & IResourceDelta.CONTENT) != IResourceDelta.CONTENT))
                               return true;
                            
                            // only interested in content changes
                            if ((delta.getFlags() & IResourceDelta.CONTENT) != IResourceDelta.CONTENT)
                               return true;
                            
                            IResource resource = delta.getResource();
                            
                            if (resource.getType() == IResource.FILE && "java".equalsIgnoreCase(resource.getFileExtension()))
                            {
                                SCCDConsole.getInstance().println(resource.getName() + " - Flags: " + delta.getFlags());
                                
                                final IFile file = (IFile) ((resource instanceof IFile) ? resource : null); 
                                
                                if (file == null)
                                    return true;
                                
                                Job job = new Job("File size check...")
                                {
                                    protected IStatus run(IProgressMonitor monitor)
                                    {
                                        try
                                        {
                                            IFileStore fileStore = org.eclipse.core.filesystem.EFS.getStore(file.getLocationURI());
                                            if (fileStore == null)
                                                return Status.OK_STATUS;
                                            long fileSize = fileStore.fetchInfo().getLength();
                                            
                                            // check if file size has changed and is not 0
                                            if (fileSize == 0 || !CloneDetectorManager.getInstance().getFileSizeManager().HasChanged(file, fileSize))
                                            {
                                                //SCCDConsole.getInstance().println(file.getName() +  " file size has not changed or is 0. Skip clone search!");
                                                return Status.OK_STATUS;
                                            }
                                            
                                            // update resource map with new file size
                                            CloneDetectorManager.getInstance().getFileSizeManager().AddOrUpdate(file, fileSize);
                                            
                                            // run code clone detection
                                            //SCCDConsole.getInstance().println(file.getName() +  " file size has changed. Running clone search!");
                                            CodeCloneDetectionJob.run(file, eScannedObjectType.File);
                                        }
                                        catch(Exception e)
                                        {
                                            e.printStackTrace();
                                        }
                                        
                                        return Status.OK_STATUS;
                                    }
                                };
                                job.schedule();
                            }
                            
                            return true;
                        }
                    
                    });
        }
        catch (Exception e)
        {
            e.printStackTrace();
        }
    }
}