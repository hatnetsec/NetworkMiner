namespace PacketParser.FileTransfer {
    public enum FileStreamTypes {
        //FtpActiveRetr,
        //FtpActiveStor,
        //FtpPassiveRetr,
        //FtpPassiveStor,
        FTP,
        HttpGetChunked,
        HttpGetNormal,
        HttpPost,
        HttpPostMimeMultipartFormData,
        HttpPostMimeFileData,
        IMAP,
        OscarFileTransfer,
        POP3,
        SMB,
        SMB2,
        SMTP,
        TFTP,
        TlsCertificate
    }
}