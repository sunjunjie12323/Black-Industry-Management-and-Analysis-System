import React from 'react';

export const AnimatedBar = (props: any) => {
  const { x, y, width, height, fill, fillOpacity, radius, index = 0, className } = props;
  return (
    <rect
      x={x} y={y} width={width} height={height}
      fill={fill} fillOpacity={fillOpacity || 1}
      rx={radius || 3}
      className={className}
    />
  );
};
