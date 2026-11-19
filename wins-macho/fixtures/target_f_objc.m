extern int printf(const char *fmt, ...);

__attribute__((objc_root_class))
@interface Greeter {
    void *isa;
    int _factor;
}
+ (instancetype)alloc;
- (instancetype)initWithFactor:(int)f;
+ (int)add:(int)a to:(int)b;
- (int)scale:(int)x;
@end

@implementation Greeter
- (instancetype)initWithFactor:(int)f {
    _factor = f;
    return self;
}
+ (int)add:(int)a to:(int)b {
    return a + b;
}
- (int)scale:(int)x {
    return x * _factor;
}
@end

int main(void) {
    int sum = [Greeter add:10 to:5];
    Greeter *g = [[Greeter alloc] initWithFactor:3];
    int scaled = [g scale:sum];
    printf("objc class=%d instance_scaled=%d\n", sum, scaled);
    return scaled;
}
