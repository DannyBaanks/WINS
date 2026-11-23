#version 420 core
layout(binding = 0) uniform sampler2D ptex0;
layout(location = 1) in vec4 vi1;
layout(location = 0) out vec4 vo0;
// Synthetic sky shader: declares ONLY SV_Target0 (location=0), omitting SV_Target1.
void main() {
    vo0 = texture(ptex0, vi1.xy);
}
