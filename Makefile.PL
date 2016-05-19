use ExtUtils::MakeMaker;

WriteMakefile (
            NAME            => 'Hep',
            VERSION_FROM    => 'lib/Hep.pm',
            AUTHOR          => 'Sebastian Damm <damm@sipgate.de>',
            ABSTRACT        => 'Lib for sending Hep packets',
            PREREQ_PM       => {
	    			'IO::Socket' => 0,
	    			'Time::HiRes' => 0,
                               },
            'dist'          => {
                                                COMPRESS => 'gzip -9f', SUFFIX => 'gz', 
                                                DIST_DEFAULT => 'tardist'
                               },
    );

