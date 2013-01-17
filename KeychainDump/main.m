//
//  main.m
//  KeychainDump
//
//  Created by Kevin Ross on 1/16/13.
//  Copyright (c) 2013 Kevin Ross. All rights reserved.
//

#import <Foundation/Foundation.h>
#import <Security/Security.h>
#import <Security/SecKeychain.h>
#import <Security/SecKeychainItem.h>
#import <Security/SecItem.h>
#import "CHCSVParser.h"

#define BAIL_ON_ERROR()	if (err != noErr) { NSLog(@"err: %d", err); return; }

void DumpKeychain()
{
	SecKeychainItemRef itemRef;
	OSStatus err;
	
	NSArray *secItemClasses = [NSArray arrayWithObjects:
							   (__bridge id)kSecClassGenericPassword,
//							   (__bridge id)kSecClassInternetPassword,
//							   (__bridge id)kSecClassCertificate,
//							   (__bridge id)kSecClassKey,
//							   (__bridge id)kSecClassIdentity,
							   nil];

	
	NSMutableDictionary *query = [NSMutableDictionary dictionaryWithObjectsAndKeys:
								  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnRef,
//								  (__bridge id)kCFBooleanTrue, (__bridge id)kSecReturnAttributes,
								  (__bridge id)kSecMatchLimitAll, (__bridge id)kSecMatchLimit,
								  nil];
	[query setObject:(__bridge id)kSecClassGenericPassword
			  forKey:(__bridge id)kSecClass];
	[query setObject:[NSNumber numberWithUnsignedInteger:'note']
			  forKey:(__bridge id)kSecAttrType];
	
	CFTypeRef result;
	err = SecItemCopyMatching((__bridge CFDictionaryRef)query, &result);
	
	NSLog(@"result: %@", result);
	BAIL_ON_ERROR();

	for (id keychainItem in (__bridge NSArray *)result) {
		SecKeychainItemRef itemRef = (__bridge SecKeychainItemRef)keychainItem;
		NSLog(@"itemRef: %@", itemRef);
		
		SecItemClass itemClass;
		SecKeychainAttributeList attrList;
		UInt32 length;
		void*  data;
		err = SecKeychainItemCopyContent(itemRef,
										 &itemClass,
										 &attrList,
										 &length,
										 &data);
		BAIL_ON_ERROR();
		
		NSString *passwdAsString = [[NSString alloc] initWithBytes:data
															length:length
														  encoding:NSUTF8StringEncoding];
		NSLog(@"passwdAsString: %@", passwdAsString);
	}
}


int main(int argc, const char * argv[])
{

	@autoreleasepool {
	    
	    // insert code here...
	    NSLog(@"Hello, World!");
	    
		DumpKeychain();
	}
    return 0;
}

