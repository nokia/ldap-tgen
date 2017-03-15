#!/usr/bin/perl -w
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#
#   psce2c
#
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### tgen2csv.pl <input_file>
#####
##### for tgen use
##### - convert to a CSV file the tgen result file 
#####
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### DEFAULT DATA
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~

# The default title for simple error responses
$errtitle= "$0 error" ;

#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### INIT
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~

#check param
( @ARGV == 0 ) && die "tgen2csv.pl <input_file> \n" ;

#pas de parametrisation
if ( $ARGV[0] =~ /^-/ ) {
    shift(@ARGV) ;
}

$inputFile = shift(@ARGV) 	;

#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### BEGIN
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~

$extension=".csv"			        ;
$csvFile = "/var/tmp/$inputFile$extension" 	;

#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### BODY
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~

CSV_build($inputFile,$csvFile) 	;

#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### SUB Carray_build
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
#####
##### 
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~

sub CSV_build {
	
    my($wfIn,$wfOut) = @_ ;
    my($running_time) ;
    
    open(WF_IN,$wfIn )
        || ciao("cannot open file handle for $wfIn : $!");    
    open(WF_OUT,"+> $wfOut");
    
    #start
    print" start to build a CSV file ... \n" ;
       
    #print date
    {
    my $date = localtime;
    #print WF_OUT "/* build by tgen2csv on $date from $inputFile \n";
    }
     
    $start_=0;
    $only_once_sr=1;
    $only_once_ss=1;
     
    while ( defined($_= <WF_IN> ) ) {
        
   	    chomp($_)	;
        
        #start with pattern "tgen running time"
	    if (/==> tgen running time: (\w*):(\w*):(\w*)/) {
	        
	        #print format
            print WF_OUT "running time\n";
                
            #print value
	        $running_time="$1:$2:$3";
	        print WF_OUT "$running_time\n";
	            
	        $start_ = 1;
	            
	    }
	    
	    #second
	    if ($start_) {
	        
                
	        #get line with at least one word followed by :
	        if (/^\w.*:/) {
	            
	            #get statistics - request
                #print value
	            if (/^(\w*).*:\s*(\d+).*:\s*(\d+).*:\s*(\d+).*:\s*(\d+).*:\s*(\d+).*:\s*(\d+).*:\s*(\d+)\.(\d+).*\(\s+(\d+)\)/) {   
	                
	                #print format
	                if ($only_once_sr) {
	                    $only_once_sr = 0;
                        print WF_OUT  " request type , mean time , min time , max time , request total number , request ko number, request retry number, over max delay (%), over max delay (number) \n";
                    }
	                
	                print WF_OUT "$1, $2, $3, $4, $5, $6, $7, $8.$9, $10 \n";  
	            }
	            
	            #get statistics - scenario
                #print value
	            if (/^(\w*)\s*: cnt:\s*(\d+)/) {

	                #print format
	                if ($only_once_ss) {
	                    $only_once_ss = 0;
                        print WF_OUT  " scenario type , execution number \n";
                    }
	                
	                print WF_OUT "$1, $2 \n";
	                
	            }      
	            
	        }
	    }        
	        
    }

    print WF_OUT "\n";
    
    close(WF_IN);
    print" CSV file is built in $csvFile\n";

}
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### SUB ciao
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### 
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~

sub ciao {

    local($msg,$title)= @_ ;
    
    $title= ($title || $errtitle || "Perl Error") 	;
    print "$title : $msg \n" 				;
    
    exit ;

}

#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~
##### THAT'S ALL FOLKS
#####~~~~~~~~~~~~~~~~~~~~~~~~~~~~   