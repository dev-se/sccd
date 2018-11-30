package de.luh.se.sccd.plugin.evaluation;

/**
 *
 * This file contains all the fixed code fragments for the vulnerabilities
 *
 */

public class EvaluationFixes
{
    // CVE-2017-9096 - Score: 6.8/10.0
    // fixed code fragment
    public void fillXfaForm(InputSource is) throws ParserConfigurationException, SAXException, IOException
    {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        DocumentBuilder db = dbf.newDocumentBuilder();
        db.setEntityResolver(new EntityResolver()
        {
            @Override
            public InputSource resolveEntity(String publicId, String systemId) throws SAXException, IOException
            {
                return new InputSource(new StringReader(""));
            }
        });
        Document newdoc = db.parse(is);
        fillXfaForm(newdoc.getDocumentElement());
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2006-2806 - Score: 7.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2006-2806
    // fixed code fragment
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
                    commandLine = commandLine.trim();
                }
                return commandLine;
            }
            catch (CRLFTerminatedReader.TerminationException te)
            {
                writeLoggedFlushedResponse("501 Syntax error at character position " + te.position()
                        + ". CR and LF must be CRLF paired.  See RFC 2821 #2.7.1.");
            }
            catch (CRLFTerminatedReader.LineLengthExceededException llee)
            {
                writeLoggedFlushedResponse("500 Line length exceeded. See RFC 2821 #4.5.3.1.");
            }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-1591 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-1591
    // fixed code fragment
    public static String randomString(int length)
    {
        if (length < 1)
        {
            return null;
        }
        // Create a char buffer to put random letters and numbers in.
        char[] randBuffer = new char[length];
        for (int i = 0; i < randBuffer.length; i++)
        {
            randBuffer[i] = numbersAndLetters[randGen.nextInt(numbersAndLetters.length - 1)];
        }
        return new String(randBuffer);
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-1217 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-1217
    // fixed code fragment
    @Override
    public String getPath(Distribution distribution)
    {
        String sversion = getVersionPart(distribution.getVersion());
        
        ArchiveType archiveType = getArchiveType(distribution);
        String sarchiveType;
        switch (archiveType)
        {
            case TGZ:
                sarchiveType = "tar.gz";
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
        
        String bitsize = "";
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
        
        String path = "postgresql-" + sversion + "-" + splatform + bitsize + "-binaries" + "." + sarchiveType;
        switch (path)
        {
            case "postgresql-10.1-1-windows-x64-binaries.zip":
                path = "postgresql-10.1-2-windows-x64-binaries.zip";
                break;
            case "postgresql-9.6.6-1-windows-x64-binaries.zip":
                path = "postgresql-9.6.6-2-windows-x64-binaries.zip";
                break;
            default:
                // no path change needed
                break;
        }
        return path;
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2007-5461 - Score: 3.5/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2007-5461
    // fixed code fragment
    /**
     * Return JAXP document builder instance.
     */
    protected DocumentBuilder getDocumentBuilder() throws ServletException
    {
        DocumentBuilder documentBuilder = null;
        DocumentBuilderFactory documentBuilderFactory = null;
        try
        {
            documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            documentBuilderFactory.setExpandEntityReferences(false);
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
    // fixed code fragment
    public Cookie(String name, String value) {
	if (!isToken(name)
		|| name.equalsIgnoreCase("Comment")	// rfc2019
		|| name.equalsIgnoreCase("Discard")	// 2019++
		|| name.equalsIgnoreCase("Domain")
		|| name.equalsIgnoreCase("Expires")	// (old cookies)
		|| name.equalsIgnoreCase("Max-Age")	// rfc2019
		|| name.equalsIgnoreCase("Path")
		|| name.equalsIgnoreCase("Secure")
		|| name.equalsIgnoreCase("Version")
		|| name.startsWith("$")
	    ) {
	    String errMsg = lStrings.getString("err.cookie_name_is_token");
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
    // fixed code fragment
    /*
     * this version is called from doPrivileged in privilegedOpenProfile. the whole
     * method is privileged!
     */
    private static FileInputStream privilegedOpenProfile(String fileName)
    {
        FileInputStream fis = null;
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
            if (!f.isFile())
            {
                // make sure file was installed in the kernel mode
                try
                {
                    // kernel uses platform independent paths =>
                    // should not use platform separator char
                    sun.jkernel.DownloadManager.downloadFile("lib/cmm/" + fileName);
                }
                catch (IOException ioe)
                {
                }
            }
        }
        
        if (f.isFile())
        {
            try
            {
                fis = new FileInputStream(f);
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
    // fixed code fragment
    public RequestDispatcher getRequestDispatcher(String path)
    {
        
        if (context == null)
            return (null);
        
        // If the path is already context-relative, just pass it through
        if (path == null)
            return (null);
        else if (path.startsWith("/"))
            return (context.getServletContext().getRequestDispatcher(path));
        
        // Convert a request-relative path to a context-relative one
        String servletPath = (String) getAttribute(Globals.INCLUDE_SERVLET_PATH_ATTR);
        if (servletPath == null)
            servletPath = getServletPath();
        
        // Add the path info, if there is any
        String pathInfo = getPathInfo();
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
            relative = requestPath.substring(0, pos + 1) + path;
        }
        else
        {
            relative = requestPath + path;
        }
        
        return (context.getServletContext().getRequestDispatcher(relative));
        
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-0846 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-0846
    // fixed code fragment
    private boolean isDeviceLocked()
    {
        boolean isLocked = false;
        final long token = Binder.clearCallingIdentity();
        try
        {
            final KeyguardManager keyguardManager = (KeyguardManager) mContext
                    .getSystemService(Context.KEYGUARD_SERVICE);
            boolean inKeyguardRestrictedInputMode = keyguardManager.inKeyguardRestrictedInputMode();
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
        finally
        {
            Binder.restoreCallingIdentity(token);
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2017-0389 - Score: 7.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2017-0389
   // fixed code fragment
    public static DhcpPacket decodeFullPacket(byte[] packet, int length, int pktType) throws ParseException
    {
        ByteBuffer buffer = ByteBuffer.wrap(packet, 0, length).order(ByteOrder.BIG_ENDIAN);
        try
        {
            return decodeFullPacket(buffer, pktType);
        }
        catch (ParseException e)
        {
            throw e;
        }
        catch (Exception e)
        {
            throw new ParseException("DHCP parsing error: %s", e.getMessage());
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2009-2693 - Score: 5.8/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2009-2693
    // fixed code fragment
    public static void unjar(InputStream in, File dest) throws IOException
    {
        if (!dest.exists())
        {
            dest.mkdirs();
        }
        if (!dest.isDirectory())
        {
            throw new IOException("Destination must be a directory.");
        }
        JarInputStream jin = new JarInputStream(in);
        byte[] buffer = new byte[1024];
        
        String canonicalDocBasePrefix = dest.getCanonicalPath();
        if (!canonicalDocBasePrefix.endsWith(File.separator))
        {
            canonicalDocBasePrefix += File.separator;
        }
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
            if (!file.getCanonicalPath().startsWith(canonicalDocBasePrefix))
            {
                throw new IOException("illegalPath: " + fileName);
            }
            if (entry.isDirectory())
            {
                // make sure the directory exists
                file.mkdirs();
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
                
                // dump the file
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
            OutputStream out = new FileOutputStream(file);
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
    // fixed code fragment
    public void setWorkDir(File workDir)
    {
        this.loaderDir = new File(workDir, "loader");
        if (loaderDir == null)
        {
            canonicalLoaderDir = null;
        }
        else
        {
            try
            {
                canonicalLoaderDir = loaderDir.getCanonicalPath();
                if (!canonicalLoaderDir.endsWith(File.separator))
                {
                    canonicalLoaderDir += File.separator;
                }
            }
            catch (IOException ioe)
            {
                canonicalLoaderDir = null;
            }
        }
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2016-6723 - Score: 5.4/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2016-6723
    // fixed code fragment
    private static String get(Uri pacUri) throws IOException
    {
        URL url = new URL(pacUri.toString());
        URLConnection urlConnection = url.openConnection(java.net.Proxy.NO_PROXY);
        long contentLength = -1;
        try
        {
            contentLength = Long.parseLong(urlConnection.getHeaderField("Content-Length"));
        }
        catch (NumberFormatException e)
        {
            // Ignore
        }
        if (contentLength > MAX_PAC_SIZE)
        {
            throw new IOException("PAC too big: " + contentLength + " bytes");
        }
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        byte[] buffer = new byte[1024];
        int count;
        while ((count = urlConnection.getInputStream().read(buffer)) != -1)
        {
            bytes.write(buffer, 0, count);
            if (bytes.size() > MAX_PAC_SIZE)
            {
                throw new IOException("PAC too big");
            }
        }
        return bytes.toString();
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2010-4172 - Score: 4.3/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2010-4172
    // fixed code fragment
    private static String localeToString(Locale locale)
    {
        if (locale != null)
        {
            return escapeXml(locale.toString());// locale.getDisplayName();
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
    // fixed code fragment
    @Override
    public String toString()
    {
        StringBuffer sb = new StringBuffer();
        for (String key : mFields.keySet())
        {
            // Don't display password in toString().
            String value = PASSWORD_KEY.equals(key) ? "<removed>" : mFields.get(key);
            sb.append(key).append(" ").append(value).append("\n");
        }
        return sb.toString();
    }
    
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    // =============================================================================================================================================================================
    
    // CVE-2011-1475 - Score: 5.0/10.0
    // Summary: Summary:
    // Url: https://www.cvedetails.com/cve-details.php?cve_id=CVE-2011-1475
    // fixed code fragment
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
            request.setCoyoteRequest(req);
            response = connector.createResponse();
            response.setCoyoteResponse(res);
            
            // Link objects
            request.setResponse(response);
            response.setRequest(request);
            
            // Set as notes
            req.setNote(ADAPTER_NOTES, request);
            res.setNote(ADAPTER_NOTES, response);
            
            // Set query string encoding
            req.getParameters().setQueryStringEncoding(connector.getURIEncoding());
        }
        
        try
        {
            connector.getService().getContainer().logAccess(request, response, time, true);
        }
        catch (Throwable t)
        {
            ExceptionUtils.handleThrowable(t);
            log.warn(sm.getString("coyoteAdapter.accesslogFail"), t);
        }
        
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
    // fixed code fragment
    /**
     * Finish AJP response.
     */
    protected void finish() throws IOException
    {
        
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
                error = true;
            }
        }
        
        if (finished)
            return;
        
        finished = true;
        
        // Swallow the unread body packet if present
        if (first && request.getContentLengthLong() > 0)
        {
            receive();
        }
        
        // Add the end message
        if (error)
        {
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
    // fixed code fragment
    /**
     * Throws a SecurityException if the permission is denied, otherwise return
     * normally. This method always denies permission to change the security manager
     * or policy.
     */
    public void checkPermission(Permission perm)
    {
        String name = perm.getName();
        
        // Enable this manually -- it'll produce too much output for -verbose
        // otherwise.
        // if (true)
        // System.out.println("Checking permission: " + perm.toString());
        
        if (!JNLPRuntime.isWebstartApplication() && ("setPolicy".equals(name) || "setSecurityManager".equals(name)))
            throw new SecurityException(R("RCantReplaceSM"));
        
        try
        {
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
            
            super.checkPermission(perm);
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
    // fixed code fragment
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
    // fixed code fragment
    private Node build(List<Node> nodes)
    {
        if (nodes.isEmpty())
        {
            return new Node(Bytes.EMPTY_HASH);
        }
        
        while (nodes.size() > 1)
        {
            List<Node> list = new ArrayList<>();
            
            for (int i = 0; i < nodes.size(); i += 2)
            {
                Node left = nodes.get(i);
                if (i + 1 < nodes.size())
                {
                    Node right = nodes.get(i + 1);
                    list.add(new Node(Hash.h256(left.value, right.value), left, right));
                }
                else
                {
                    list.add(new Node(left.value, left, null));
                }
            }
            
            levels++;
            nodes = list;
        }
        
        levels++;
        return nodes.get(0);
    }
}