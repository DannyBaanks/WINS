#version 420 core
layout(binding = 0) uniform sampler2D ptex0;
layout(location = 1) in vec4 vi1;
layout(location = 0) out vec4 vo0;
// Synthetic bloom extract shader reading RT1 (tex=101).
void main() {
    vec4 c = texture(ptex0, vi1.xy);
    vo0 = vec4(c.rgb * c.a, 1.0);
}
