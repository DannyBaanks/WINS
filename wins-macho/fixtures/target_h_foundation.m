typedef unsigned long size_t;

typedef unsigned long NSUInteger;
typedef long NSInteger;
typedef signed char BOOL;
#define YES ((BOOL)1)
#define NO ((BOOL)0)

typedef struct _NSRange {
    NSUInteger location;
    NSUInteger length;
} NSRange;

extern int printf(const char *fmt, ...);
extern int memcmp(const void *s1, const void *s2, size_t n);

@class NSString, NSData, NSArray, NSMutableArray, NSAutoreleasePool;

@interface NSObject {
    void *isa;
}
+ (instancetype)alloc;
+ (instancetype)new;
+ (Class)class;
- (instancetype)init;
- (void)dealloc;
- (instancetype)retain;
- (oneway void)release;
- (instancetype)autorelease;
- (NSUInteger)retainCount;
- (Class)class;
- (BOOL)isKindOfClass:(Class)aClass;
- (BOOL)respondsToSelector:(SEL)aSelector;
- (BOOL)isEqual:(id)object;
- (NSString *)description;
@end

@interface NSString : NSObject
+ (instancetype)stringWithUTF8String:(const char *)nullTerminatedCString;
+ (instancetype)stringWithFormat:(NSString *)format, ...;
- (NSUInteger)length;
- (const char *)UTF8String;
- (BOOL)isEqualToString:(NSString *)aString;
- (NSString *)stringByAppendingString:(NSString *)aString;
- (BOOL)hasPrefix:(NSString *)str;
- (BOOL)containsString:(NSString *)str;
- (NSInteger)integerValue;
- (NSData *)dataUsingEncoding:(NSUInteger)encoding;
@end

@interface NSData : NSObject
+ (instancetype)dataWithBytes:(const void *)bytes length:(NSUInteger)length;
- (NSUInteger)length;
- (const void *)bytes;
- (BOOL)isEqualToData:(NSData *)otherData;
- (NSData *)subdataWithRange:(NSRange)range;
@end

@interface NSArray : NSObject
+ (instancetype)arrayWithObjects:(const id *)objects count:(NSUInteger)cnt;
- (NSUInteger)count;
- (id)objectAtIndex:(NSUInteger)index;
- (id)objectAtIndexedSubscript:(NSUInteger)idx;
- (BOOL)containsObject:(id)anObject;
- (NSString *)componentsJoinedByString:(NSString *)separator;
@end

@interface NSMutableArray : NSArray
+ (instancetype)arrayWithCapacity:(NSUInteger)numItems;
- (void)addObject:(id)anObject;
- (void)removeObjectAtIndex:(NSUInteger)index;
@end

@interface NSAutoreleasePool : NSObject
- (void)drain;
@end

extern void NSLog(NSString *format, ...);

static int g_dealloc_count = 0;

@interface CounterItem : NSObject {
    int _value;
}
- (instancetype)initWithValue:(int)v;
- (int)value;
@end

@implementation CounterItem
- (instancetype)initWithValue:(int)v {
    self = [super init];
    if (self) {
        _value = v;
    }
    return self;
}
- (int)value {
    return _value;
}
- (NSString *)description {
    return [NSString stringWithFormat:@"Counter(%d)", _value];
}
- (void)dealloc {
    g_dealloc_count++;
    [super dealloc];
}
@end

int main(void) {
    NSAutoreleasePool *pool = [[NSAutoreleasePool alloc] init];

    // 1. NSString literals & dynamic strings
    NSString *lit = @"WINS";
    NSString *dyn = [NSString stringWithUTF8String:"MachO"];
    NSString *joined = [[lit stringByAppendingString:@"-"] stringByAppendingString:dyn];
    if (![joined isEqualToString:@"WINS-MachO"]) return 10;
    if (![joined hasPrefix:@"WINS"] || ![joined containsString:@"MachO"]) return 11;
    if ([@"42" integerValue] != 42) return 12;

    // 2. NSData
    NSData *d1 = [joined dataUsingEncoding:4];
    NSData *d2 = [NSData dataWithBytes:"WINS-MachO" length:10];
    if (![d1 isEqualToData:d2]) return 20;
    NSRange r = { 5, 5 };
    NSData *sub = [d1 subdataWithRange:r];
    if ([sub length] != 5 || memcmp([sub bytes], "MachO", 5) != 0) return 21;

    // 3. NSObject subclass, super init, retain/release, description, autorelease
    CounterItem *item = [[CounterItem alloc] initWithValue:7];
    if (![item isKindOfClass:[NSObject class]]) return 30;
    if (![item respondsToSelector:@selector(value)]) return 31;
    if ([item value] != 7) return 32;
    [item autorelease];

    // 4. NSArray literal + NSMutableArray + fast enumeration
    NSArray *arr = @[ @"alpha", @"beta", item ];
    if ([arr count] != 3) return 40;
    if (![arr[1] isEqualToString:@"beta"]) return 41;
    if (![arr containsObject:@"alpha"]) return 42;

    NSMutableArray *marr = [NSMutableArray arrayWithCapacity:2];
    [marr addObject:@"one"];
    [marr addObject:@"two"];
    [marr addObject:@"three"];
    [marr removeObjectAtIndex:1];
    NSString *csv = [marr componentsJoinedByString:@","];
    if (![csv isEqualToString:@"one,three"]) return 43;

    NSUInteger enum_count = 0;
    for (id obj in arr) {
        if (obj) enum_count++;
    }
    if (enum_count != 3) return 44;

    // 5. NSLog with %@ and %lu
    NSLog(@"Foundation OK: %@ | %@ | len=%lu", joined, csv, (unsigned long)[sub length]);

    // Keep joined & csv alive across pool drain via explicit retain
    [joined retain];
    [csv retain];

    [pool drain];

    // item was autoreleased, then retained/released by arr; after pool drain it should be deallocated!
    if (g_dealloc_count != 1) {
        printf("unexpected dealloc count: %d\n", g_dealloc_count);
        return 50;
    }

    printf("foundation_ok joined=%s csv=%s dealloc=%d\n", [joined UTF8String], [csv UTF8String], g_dealloc_count);
    [joined release];
    [csv release];
    return 0;
}
