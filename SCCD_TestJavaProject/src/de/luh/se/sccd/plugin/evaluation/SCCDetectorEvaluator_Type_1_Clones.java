package de.luh.se.sccd.plugin.evaluation;

/**
 *
 * This file contains all the vulnerable code fragments as type-1 clones
 *
 */

public class SCCDetectorEvaluator_Type_1_Clones
{
    // CVE-2017-9096 - Score: 6.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-9096
    // vulnerable code fragment
    public void fillXfaForm(InputSource is) throws ParserConfigurationException, SAXException, IOException
    {
        // a comment inside type-1 clone
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();

            Document newdoc = db.parse(is);




        fillXfaForm(newdoc.getDocumentElement());
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
                String commandLine = inReader.readLine();
                if (commandLine != null)
                {


                    commandLine = commandLine.trim(); // some comment
                }
                return commandLine;
            }
            catch (CRLFTerminatedReader.TerminationException te)
            {
                writeLoggedFlushedResponse("501 Syntax error at character position " + te.position()
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
        // Create a char buffer to put random letters and numbers in.
        char[] randBuffer = new char[length];
        for (int i = 0; i < randBuffer.length; i++)
        {
            randBuffer[i] = numbersAndLetters[randGen.nextInt(71)];
        }
        return new String(randBuffer);
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
        String sversion = getVersionPart(distribution.getVersion());
        
        ArchiveType archiveType = getArchiveType(distribution);
        String sarchiveType;
        switch (archiveType)
        {
            case TGZ:
                sarchiveType = "tar.gz"; // sarchiveType = "tar.gz";
                break;
            case ZIP:
                sarchiveType = "zip";
                break;
            default:
                throw new IllegalArgumentException("Unknown ArchiveType " + archiveType);
        }
        
            String splatform;
        switch (distribution.getPlatform())
        {
            case Linux:
                splatform = "linux";
                break;
            case Windows:
                splatform = "windows";
                break;
            case OS_X:
                splatform = "osx";
                break;
            default:
                throw new IllegalArgumentException("Unknown Platform " + distribution.getPlatform());
        }




        
            String bitsize = ""; // String bitsize = "";
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
                        bitsize = "-x64";
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
        
        // just a comment return "postgresql-" 
        return "postgresql-" + sversion + "-" + splatform + bitsize + "-binaries" + "." + sarchiveType;
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
        DocumentBuilder documentBuilder = null;

        DocumentBuilderFactory documentBuilderFactory = null;
        try
        {
            // the comment goes here...
            documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            documentBuilder = documentBuilderFactory.newDocumentBuilder();
        }
        catch (ParserConfigurationException e)
        {
            throw new ServletException(sm.getString("webdavservlet.jaxpfailed"));
        }
        return documentBuilder;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2007-6203 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2007-6203
    // vulnerable code fragment
    public Cookie(String name, String value) {
	if (!isToken(name)
		|| name.equalsIgnoreCase("Comment")	// Old and new rfc2019
		|| name.equalsIgnoreCase("Discard")	// 2019++ akdjhfkhfdskhfd
		|| name.equalsIgnoreCase("Domain") // this is new
		|| name.equalsIgnoreCase("Expires")	// ok, a comment goes here (old cookies)
		|| name.equalsIgnoreCase("Max-Age")	// rfc2019
		|| name.equalsIgnoreCase("Path")
		|| name.equalsIgnoreCase("Secure") // also a new comment
		|| name.equalsIgnoreCase("Version")
		|| name.startsWith("$")
	    ) {
	    String errMsg = lStrings.getString("err.cookie_name_is_token");
	    Object[] errArgs = new Object[1];
	    errArgs[0] = name;
	    errMsg = MessageFormat.format(errMsg, errArgs);
	    throw new IllegalArgumentException(errMsg);
	}

	this.name = name;
	this.value = value;
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
        FileInputStream fis = null; // abcd
        String path, dir, fullPath;
        
        File f = new File(fileName); /* try absolute file name */
        
        if ((!f.isFile()) && ((path = System.getProperty("java.iccprofile.path")) != null))
        {
            /* try relative to java.iccprofile.path */
            StringTokenizer st = new StringTokenizer(path, File.pathSeparator);
            while (st.hasMoreTokens() && (!f.isFile()))
            {
                dir = st.nextToken();

                fullPath = dir + File.separatorChar + fileName;
                f = new File(fullPath);
            }
        }
        
        // 49857459873459843753498573498 comment addded
        if ((!f.isFile()) && ((path = System.getProperty("java.class.path")) != null))
        {
            /* try relative to java.class.path */
            StringTokenizer st = new StringTokenizer(path, File.pathSeparator);
            while (st.hasMoreTokens() && (!f.isFile()))
            {
                dir = st.nextToken();

                fullPath = dir + File.separatorChar + fileName;
                f = new File(fullPath);
            }
        }
        
        if (!f.isFile())
        { /* try the directory of built-in profiles */
            dir = System.getProperty("java.home") + File.separatorChar + "lib" + File.separatorChar + "cmm";
            fullPath = dir + File.separatorChar + fileName;
            f = new File(fullPath);
        }
        
        if (f.isFile())
        {
            try
            {
                fis = new FileInputStream(f); // the stream comment
            }
            catch (FileNotFoundException e)
            {
            }
        }
        return fis;
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
        // added comment an after that do an NULL check
        if (context == null)
            return (null);
        
        // If the path is already context-relative, just pass it through
        if (path == null)
            return (null);
        else if (path.startsWith("/"))            
            return (context.getServletContext().getRequestDispatcher(path));
        





        
        String servletPath = (String) getAttribute(Globals.INCLUDE_SERVLET_PATH_ATTR); // Convert a request-relative path to a context-relative one
        if (servletPath == null)
            servletPath = getServletPath();
        
        
        String pathInfo = getPathInfo();// Add the path info, if there is any
        String requestPath = null;
        
        if (pathInfo == null)
        {

            requestPath = servletPath;
        }
        else
        {

            requestPath = servletPath + pathInfo;
        }
        
        int pos = requestPath.lastIndexOf('/');
        String relative = null;
        if (pos >= 0)
        {
            relative = RequestUtil.normalize(requestPath.substring(0, pos + 1) + path);
        }
        else
        {
            relative = RequestUtil.normalize(requestPath + path);
        }
        
        return (context.getServletContext().getRequestDispatcher(relative));
        
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
        boolean isLocked = false;
        KeyguardManager keyguardManager = (KeyguardManager) mContext.getSystemService(Context.KEYGUARD_SERVICE);
        boolean inKeyguardRestrictedInputMode = keyguardManager.inKeyguardRestrictedInputMode()
        ;
        if (inKeyguardRestrictedInputMode)
        {
            isLocked = true;
        }
        else
        {
            
            PowerManager powerManager = (PowerManager) mContext.getSystemService(Context.POWER_SERVICE);
            isLocked = !powerManager.isScreenOn();
        }
        return isLocked;
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
        ByteBuffer buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN);



                return decodeFullPacket(buffer, pktType);
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
            // throw now comment
            throw new IOException("Destination must be a directory.");
        }
        JarInputStream jin = new JarInputStream(in);
        byte[] buffer = new byte[1024];
        
        ZipEntry entry = jin.getNextEntry();
        while (entry != null)
        {
            String fileName = entry.getName();
            if (fileName.charAt(fileName.length() - 1) == '/')
            {
                fileName = fileName.substring(0, fileName.length() - 1);

            }
            if (fileName.charAt(0) == '/')
            {
                fileName = fileName.substring(1);

            }
            if (File.separatorChar != '/')
            {
                fileName = fileName.replace('/', File.separatorChar);
            }
            File file = new File(dest, fileName);
            if (entry.isDirectory())
            {
                
                file.mkdirs(); // 0815 - make sure the directory exists
                jin.closeEntry();
            }
            else
            {
                // make sure the directory exists
                File parent = file.getParentFile();
                if (parent != null && !parent.exists())
                {
                    parent.mkdirs();
                }
                
                // dump the file indentions
                                OutputStream out = new FileOutputStream(file);
                int len = 0;
                while ((len = jin.read(buffer, 0, buffer.length)) != -1)
                {
                    out.write(buffer, 0, len);
                }
                out.flush();
                out.close();
                jin.closeEntry();
                file.setLastModified(entry.getTime());
            }
            entry = jin.getNextEntry();
        }
        /*
         * Explicity write out the META-INF/MANIFEST.MF so that any headers such as the
         * Class-Path are see for the unpackaged jar
         */
        Manifest mf = jin.getManifest();
        if (mf != null)
        {
            File file = new File(dest, "META-INF/MANIFEST.MF");
            File parent = file.getParentFile();
            if (parent.exists() == false)

            {
                parent.mkdirs();
            }
            OutputStream out = new FileOutputStream(file); // ok comment
            mf.write(out);

            out.flush();
            out.close();
        }
        jin.close();
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2009-2901 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2901
    // vulnerable code fragment
    public void setWorkDir(File workDir)
    {

        this.loaderDir = new File(workDir, "loader");
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
        URL url = new URL(pacUri.toString());
        URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
        return new String(Streams.readFully(urlConnection.getInputStream())); // the comment for type-1 clone
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
            // the following comment seems to be old code
            return locale.toString();// locale.getDisplayName();
        }
        else
        {
            return "";
        }
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
        StringBuffer sb = new StringBuffer();
        for (String key : mFields.keySet())
        {


            // append it now comment
            sb.append(key).append(" ").append(mFields.get(key)).append("\n");
        }

        return sb.toString();
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
        
        Request request = (Request) req.getNote(ADAPTER_NOTES);
        Response response = (Response) res.getNote(ADAPTER_NOTES);
        boolean create = false;
        
        if (request == null)
        {
            create = true;
            // Create objects
            request = connector.createRequest();

            request.setCoyoteRequest(req); // crt objs
            response = connector.createResponse();

            response.setCoyoteResponse(res);
            

            // Link objects
            request.setResponse(response);
            
            response.setRequest(request); // links comment
            
            // Set as notes
            req.setNote(ADAPTER_NOTES, request);
            
            res.setNote(ADAPTER_NOTES, response);
            
            // The old comment was removed totally
            


            req.getParameters().setQueryStringEncoding(connector.getURIEncoding());
        }
        
        connector.getService().getContainer().logAccess(request, response, time, true);
        
        if (create)
        {
            request.recycle();
            response.recycle();
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
        // new indention
                            if (!response.isCommitted())
        {
            // Validate and write response headers
            try
            {
                prepareResponse();
            }
            catch (IOException e)
            {
                // Set error flag
                error = true; // and now it's true
            }
        }
        
        if (finished)
            return;
        
        finished = true;
        
        // comment removed and added below
        if (error)
        {
            // this is new
            output(endAndCloseMessageArray, 0, endAndCloseMessageArray.length);
        }
        else
        {
            output(endMessageArray, 0, endMessageArray.length);
        }
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
    public void checkPermission(Permission perm)
    {
        String name = perm.getName();
        
        // the follwing four comment lines are removed
        

        if (!JNLPRuntime.isWebstartApplication() && ("setPolicy".equals(name) || "setSecurityManager".equals(name)))
            throw new SecurityException(R("RCantReplaceSM"));
        
        try
        {
            // The followin ten comment lines are removed and added at other line s
            
            
            try
            {
                super.checkPermission(perm);
            }
            catch (SecurityException se)
            {
                
                // This section is a special case for dealing with SocketPermissions.
                if (JNLPRuntime.isDebug())
                    System.err.println("Requesting permission: " + perm.toString());
                    
                // Change this SocketPermission's action to connect and accept
                // (and resolve). This is to avoid asking for connect permission
                // on every address resolve.
                Permission tmpPerm = null;
                if (perm instanceof SocketPermission)
                {
                    tmpPerm = new SocketPermission(perm.getName(), SecurityConstants.SOCKET_CONNECT_ACCEPT_ACTION);
                    
                    // before proceeding, check if we are trying to connect to same origin
                    ApplicationInstance app = getApplication();
                    JNLPFile file = app.getJNLPFile();
                    

                    String srcHost = file.getSourceLocation().getAuthority();
                    String destHost = name;
                    
                    // host = abc.xyz.com or abc.xyz.com:<port>
                    if (destHost.indexOf(':') >= 0)
                        destHost = destHost.substring(0, destHost.indexOf(':'));
                    
                    // host = abc.xyz.com
                    String[] hostComponents = destHost.split("\\.");
                    
                    int length = hostComponents.length;
                    if (length >= 2)
                    {

                        
                        // address is in xxx.xxx.xxx format
                        destHost = hostComponents[length - 2] + "." + hostComponents[length - 1];
                        

                        // host = xyz.com i.e. origin
                        boolean isDestHostName = false;
                        
                        // make sure that it is not an ip address
                        try
                        {
                            Integer.parseInt(hostComponents[length - 1]);
                        }
                        catch (NumberFormatException e)
                        {
                            isDestHostName = true;

                            // here is a comment from above
                            // deny all permissions to stopped applications
            // The call to getApplication() below might not work if an
            // application hasn't been fully initialized yet.
            // if (JNLPRuntime.isDebug()) {
            // if (!"getClassLoader".equals(name)) {
            // ApplicationInstance app = getApplication();
            // if (app != null && !app.isRunning())
            // throw new SecurityException(R("RDenyStopped"));
            // }
            // }
                        }
                        



                        if (isDestHostName)
                        {
                            // okay, destination is hostname. Now figure out if it is a subset of origin
                            if (srcHost.endsWith(destHost))
                            {
                                addPermission(tmpPerm);
                                return;
                            }
                        }
                    }
                }
                else
                {
                    tmpPerm = perm;
                }
                
                if (tmpPerm != null)
                {
                    // askPermission will only prompt the user on SocketPermission
                    // meaning we're denying all other SecurityExceptions that may arise.
                    if (askPermission(tmpPerm))
                    {
                        addPermission(tmpPerm);
                        // return quietly.
                    }
                    else
                    {
                        throw se;
                    }
                }
            }
        }
        catch (SecurityException ex)
        {
            if (JNLPRuntime.isDebug())
            {
                System.out.println("Denying permission: " + perm);
            }
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
    public static void readOperations(Element simpleMethodElement, List<MethodOperation> methodOperations,
            SimpleMethod simpleMethod)
    {
        List<? extends Element> operationElements = UtilXml.childElementList(simpleMethodElement);
        
        if (UtilValidate.isNotEmpty(operationElements))
        {
            for (Element curOperElem : operationElements)
            {
                String nodeName = curOperElem.getNodeName();
                MethodOperation methodOp = null;

                // a comment
                // with more
                // than one line
                // as type-1 clone
                
                MethodOperation.Factory<MethodOperation> factory = methodOperationFactories.get(nodeName);
                if (factory != null)
                {
                    methodOp = factory.createMethodOperation(curOperElem, simpleMethod);
                }
                else if ("else".equals(nodeName))
                {
                    // don't add anything, but don't complain either, this one is handled in the
                    // individual operations
                }
                else
                {
                    Debug.logWarning("Operation element \"" + nodeName + "\" no recognized", module);
                }
                if (methodOp == null)
                    continue;
                if (UtilProperties.propertyValueEquals("webslinger-invoker.properties", "wrap-calls", "true"))
                {


                    Wrap<MethodOperation> wrap = new Wrap<MethodOperation>().fileName(simpleMethod.getLocationAndName())
                            .wrappedClass(methodOp.getClass());

                    wrap.wrap(methodOperationExecMethod);

                    Object startLine = curOperElem.getUserData("startLine");

                    if (startLine != null)
                    {
                        wrap.lineNumber(((Integer) startLine).intValue()); // comment added
                    }
                    methodOp = wrap.newInstance(new Class<?>[] { Element.class, SimpleMethod.class },
                            new Object[] { curOperElem, simpleMethod });
                }
                methodOperations.add(methodOp);

                DeprecatedOperation depOp = methodOp.getClass().getAnnotation(DeprecatedOperation.class);
                if (depOp != null)
                    Debug.logInfo("The " + nodeName + " operation has been deprecated in favor of the " + depOp.value()
                            + " operation; found use of this in [" + simpleMethod.getShortDescription() + "]: "
                            + methodOp.rawString(), module);
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
    private Node build(List<Node> nodes)
    {
        if (nodes.isEmpty())
        {
            return new Node(Bytes.EMPTY_HASH);
        }
        
        while (nodes.size() > 1)
        {
            List<Node> list = new ArrayList<>();
            
            // duplicate the last element when the number of elements is odd.
            if (nodes.size() % 2 != 0)
            {




                nodes.add(new Node(nodes.get(nodes.size() - 1).value)); // shallow copy comment moved
            }
            
            for (int i = 0; i < nodes.size() - 1; i += 2)
            {

                Node left = nodes.get(i);

                Node right = nodes.get(i + 1);



                list.add(new Node(Hash.h256(left.value, right.value), left, right));
            }
            
            levels++;

            nodes = list;
        }
        
        levels++;
        return nodes.get(0);
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