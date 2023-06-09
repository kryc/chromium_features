# Chromium Feature Enumeration
It is difficult to enumerate feature flags as not all features are covered in chrome://flags.

# How it works

This script uses compiltion patterns in the .text, .data and .rdata segments to enumerate a list of all feature flags for Chromium browsers. It relies on knowing a single feature flag to work backwards and discover the rest. Fortunately, Microsoft's naming convention of ms* makes this significantly easir on Edge. It does not matter which flag we use, we just need one valid flag name to crib from. It then uses the offset of this string to find its associated base::Feature object in the .data section.

Armed with this knowledge we can scrape the entirety of the .text section for sequences of instructions which load effective address (lea) rcx, (this) then make a subsequent call. The call will be to base::Feature::IsEnabled. Thus:

```x86
lea rcx, [imm]; //feature offset
xor rdx, rdx;
call base::Feature::IsEnabled;
```

Once we have the address of IsEnabled, we can then perform one more pass over the .text section and find all calls to base::Feature::IsEnabled, the immediate value passed to the prior lea instruction contains the offset of the Feature (and thus a pointer to the name).

# Sample Output
Taken from Edge 113.0.1774.42
```text
0x18e265498 SwipeToMoveCursor
0x18e2716a8 msEdgeContinuousMigrationEngagementExperience
0x18e271690 msEdgeContinuousMigrationExperience
0x18e217b30 msBypassEnterpriseCheckForPermaEdgeTesting
0x18e1de130 OriginAgentClusterDefaultWarning
0x18e265288 kReducedFrameRateEstimation
0x18e1de460 TimedHTMLParserBudget
0x18e1de478 CheckHTMLParserBudgetLessOften
0x18e27ce40 AutofillEnableDevtoolsIssues
0x18e27cc48 AutofillAcrossIframes
0x18e27cf78 AutofillImprovedLabelForInference
0x18e265270 MoreAggressiveSolidColorDetection
0x18e1dd908 DecodeJpeg420ImagesToYUV
0x18e1dd920 DecodeLossyWebPImagesToYUV
0x18e266480 PrivateStateTokens
0x18e266498 TrustTokens
0x18e27d3c8 msEdgeFluentOverlayScrollbar
0x18e1e1640 FedCm
0x18e1de340 PendingBeaconAPI
0x18e1df2e8 Portals
0x18e1e1c40 PrivacySandboxAdsAPIsOverride
0x18e1dd6c8 FencedFrames
0x18e1ddf20 BrowsingTopics
0x18e1ddf38 BrowsingTopicsXHR
0x18e1ddf08 AllowURNsInIframes
0x18e1e1b20 OriginIsolationHeader
0x18e1de118 OriginAgentClusterDefaultEnable
0x18e2069b0 NewBrowsingContextStateOnBrowsingContextGroupSwap
0x18e218420 BlinkSchedulerMicroTaskRejectPromisesOnEachCompletion
0x18e291d08 msBingGECHeader
0x18e260e88 CaseInsensitiveCookiePrefix
0x18e2654c8 RawDraw
0x18e2651f8 UseDMSAAForTiles
0x18e20dfa8 msWalletSelfhost
0x18e27c6c8 msUkmGovernanceList
0x18e27c6b0 msHistogramsGovernanceList
0x18e27c698 msUserActionsGovernanceList
0x18e250b58 msEdgeSplitWindow
0x18e1d27a8 MultiPlaneSoftwareVideoSharedImages
0x18e260600 msMfAacDecoding
0x18e1d2d18 MediaFoundationBatchRead
0x18e1dc968 msEdgeDesignerUI
...
```
