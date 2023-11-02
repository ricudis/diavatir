#!/usr/bin/env python3
import math
import sys
import dlib
import cv2
import openface
import matplotlib.pyplot as plt
from matplotlib.animation import FuncAnimation
import numpy as np
from dataclasses import dataclass

class Moutsounodata:
  def __init__(self):
    self.min_diff = 1
    self.min_diffs = []
    self.diffs = []
    self.pos = 0
    self.neg = 0
    self.line_img = None
    self.line_graph_diff = None
    self.line_graph_min_diff = None
    self.line_graph_threshold = None
  
class Moutsouna: 
  def __init__(self):
    self.colors = ((255, 0, 0),
          (0, 255, 0),
          (0, 0, 255),
          (255, 128, 128),
          (255, 0, 255),
          (0, 255, 255),
          (255, 128, 255),
          (0, 0, 0),
          (255, 255, 255))
    self.face_detector = dlib.get_frontal_face_detector()
    self.face_aligner = openface.AlignDlib("./openface/models/dlib/shape_predictor_68_face_landmarks.dat")
    self.face_encoder = dlib.face_recognition_model_v1("./openface/models/dlib/dlib_face_recognition_resnet_model_v1.dat")
    self.frame_no = 0
    self.pct_frames = 0
    self.threshold = 0.6
    self.window = 100
    self.ref_fnames = ['AN5340122276062722205290-mutsuna.png',
              '49517979_10157771625099625_1410031861991735296_n.jpg',
              '1008233_10152095259221040_1029985496_o.jpg',
              'russell-crowe-655563de9223497f8efebefe05dce08f.jpg',
              'mitsotakis__2_.jpg',
              'GettyImages-1349540055-e1695936847143.jpg']
    self.n_imgs = len(self.ref_fnames)
    self.fig = plt.figure(layout='constrained', figsize=(12.80,10.24))
    self.subfigs = self.fig.subfigures(1, 2, width_ratios=[1, 2])
    self.subfigsnest = self.subfigs[0].subfigures(2, 1, height_ratios=[1, 1.4])
    self.ax_vid = self.subfigsnest[0].add_subplot()
    self.ax_vid.tick_params(labelbottom=False, labelleft=False)
    self.axs_graph = self.subfigsnest[1].subplots(self.n_imgs, 1, sharex=True)
    self.axs_img = self.subfigs[1].subplots(2, math.ceil(self.n_imgs/2)).flatten()
    for idx, ax in enumerate(self.axs_img):
      ax.tick_params(labelbottom=False, labelleft=False)
    self.line_vid = None
    self.moutsounarray = []
    self.ref_encodings = []
    self.x = []
    self.last_dref = []
    
    print("initializing video capture")

    self.video_capture = cv2.VideoCapture(0)
    self.video_capture.set(3,640) # set Width
    self.video_capture.set(4,480) # set Height
    
    for idx, fname in enumerate(self.ref_fnames):
      print("Reading ", fname)
      
      md = Moutsounodata()
      
      ref_img = cv2.cvtColor(cv2.imread(fname), cv2.COLOR_BGR2RGB)
      (ref_img, encodings) = self.process_image(ref_img, self.colors[idx])
      
      self.ref_encodings.append(encodings)
      md.line_img = self.axs_img[idx].imshow(ref_img)
      md.ref_img = ref_img
      
      self.axs_graph[idx].set_ylim(0, 1)
      self.axs_graph[idx].set_xlim(0, self.window)
      
      md.line_graph_diffs, = self.axs_graph[idx].plot([], [], c=self.conv_color(self.colors[idx]))
      
      md.line_graph_min_diffs, = self.axs_graph[idx].plot([], [], c='k')
      self.moutsounarray.append(md)
      self.last_dref.append(1.0)
      
    result, frame = self.video_capture.read()
    cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
    self.line_vid = self.ax_vid.imshow(frame)
    

  def face_encodings(self, aligned_face_image, num_jitters=1):
      return np.array(self.face_encoder.compute_face_descriptor(aligned_face_image, num_jitters))
          

  def draw_landmark(self, img, landmarks, rng, is_closed, clr):
    (x, y) = (0, 0)
    (x0, y0) = (0, 0) 
    for i in rng:
      (x1, y1) = (landmarks[i][0], landmarks[i][1])
      if (is_closed and x0 == 0 and y0 == 0):
        x0 = x1
        y0 = y1
      if (x > 0 and y > 0) :
        cv2.line(img, (x, y), (x1, y1), clr, 1)
      x = x1
      y = y1 
    if (is_closed):
      cv2.line(img, (x1, y1), (x0, y0), clr, 1)


  def draw_landmarks(self, img, landmarks, clr):
    self.draw_landmark(img, landmarks, range(0, 16), False, clr)
    self.draw_landmark(img, landmarks, range(17, 21), False, clr)
    self.draw_landmark(img, landmarks, range(22, 26), False, clr)
    self.draw_landmark(img, landmarks, range(27, 30), False, clr)
    self.draw_landmark(img, landmarks, range(31, 35), False, clr)
    self.draw_landmark(img, landmarks, range(36, 41), True, clr)
    self.draw_landmark(img, landmarks, range(42, 47), True, clr)
    self.draw_landmark(img, landmarks, range(48, 59), True, clr)
    self.draw_landmark(img, landmarks, range(60, 67), True, clr)


  def conv_color(self, khromatakkhi):
    return ((khromatakkhi[0]/255, 
            khromatakkhi[1]/255,
            khromatakkhi[2]/255))


  def process_image(self, img, clr):
    detected_faces = self.face_detector(img, 0)

    if (len(detected_faces) < 1):
        return (img, None)

    bounding_box = detected_faces[0]
  
    cv2.rectangle(img, (bounding_box.left(), bounding_box.bottom()), (bounding_box.right(), bounding_box.top()), clr, 4)    
    
    # Get face landmarks
    lalalandmarks = self.face_aligner.findLandmarks(img, bounding_box)
    self.draw_landmarks(img, lalalandmarks, clr)
    
    # Align image
    aligned_img = self.face_aligner.align(150, img, bounding_box, lalalandmarks, landmarkIndices=openface.AlignDlib.OUTER_EYES_AND_NOSE, skipMulti=True)
    
    # Get face encodings from aligned image
    encodings = self.face_encodings(aligned_img, 1)
    
    if (img.shape[1] > aligned_img.shape[1] and img.shape[0] > aligned_img.shape[0]):
      img[0:aligned_img.shape[1], 0:aligned_img.shape[0]] = aligned_img
      cv2.rectangle(img, (0, 0), (aligned_img.shape[1], aligned_img.shape[0]), clr, 2)

    return (img, encodings)
    

  def face_distance(self, face_encodings, face_to_compare):
    if len(face_encodings) == 0:
        return np.empty((0))
    return np.linalg.norm(face_encodings - face_to_compare, axis=1)


  def frame_init(self):
    ret = []
    
    for idx, fname in enumerate(self.ref_fnames):
      md = self.moutsounarray[idx]
      self.axs_graph[idx].set_ylim(0, 1)
      self.axs_graph[idx].set_xlim(0, 100)
      md.line_graph_diffs = self.axs_graph[idx].plot([], [], c=self.conv_color(self.colors[idx]))[0]
      md.line_graph_min_diffs = self.axs_graph[idx].plot([], [], c='k')[0]
      md.line_graph_threshold = self.axs_graph[idx].axhline(y = self.threshold, color = 'k', linestyle = 'dashed')

      ret.append(md.line_graph_diffs)
      ret.append(md.line_graph_min_diffs)
      ret.append(md.line_graph_threshold)

    return ret
    

  def qumbi(self, event):
    if (event.key == 'q'):
        plt.close(event.canvas.figure)
        return
    elif (event.key == 'i'):
        self.threshold += 0.1
    elif (event.key == 'd'):
        self.threshold -= 0.1
    elif (event.key == 'r'):
        pass
        
    print("Threshold : ", self.threshold)
    self.pct_frames = 0
    for idx, fname in enumerate(self.ref_fnames):
      md = m.moutsounarray[idx]
      md.line_graph_threshold.set_ydata([self.threshold] * 2)
      md.pos = 0
      md.neg = 0
 
  def frame_update(self, i):
    result, frame = self.video_capture.read()

    if result is False:
        return None
        
    frame = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        
    (img, encodings) = self.process_image(frame, self.conv_color(self.colors[7]))

    ret = []
    self.line_vid.set_data(img)
    ret.append(self.line_vid)
    
    if (encodings is None):
        for idx, fname in enumerate(self.ref_fnames):
            md = m.moutsounarray[idx]
            ret.append(md.line_img)
            ret.append(md.line_graph_diffs)
            ret.append(md.line_graph_min_diffs)
            ret.append(md.line_graph_threshold)
        return ret
    
    dref = self.face_distance(self.ref_encodings, encodings)
    print(dref)

    self.frame_no += 1
    self.pct_frames += 1
    self.x.append(self.frame_no)
    self.x = self.x[-self.window:]
    
    for idx, d in enumerate(dref):
        md = m.moutsounarray[idx]
        
        if d < self.threshold:
          md.pos += 1
        else : 
          md.neg += 1

        pct = 100 * md.pos / self.pct_frames

        md.min_diff = min(d, md.min_diff)
        md.min_diffs.append(md.min_diff)
        md.diffs.append(d)
    
        txt = f't={self.threshold:.2f} d={d:.2f} dmin={md.min_diff:.2f} pct={pct:2.2f}%'

        md.diffs = md.diffs[-self.window:]
        md.min_diffs = md.min_diffs[-self.window:]

        self.axs_graph[idx].set_xlim(self.x[0], self.x[-1])
        
        img1 = md.ref_img.copy()
        
        cv2.putText(img1, txt, (10, (frame.shape[0]-10)), cv2.FONT_HERSHEY_SIMPLEX, 0.6, self.colors[idx], 2, cv2.LINE_AA)
        cv2.putText(img1, txt, (10, (frame.shape[0]-10)), cv2.FONT_HERSHEY_SIMPLEX, 0.6, self.colors[8], 1, cv2.LINE_AA)
        
        md.line_img.set_data(img1)
        ret.append(md.line_img)
        
        md.line_graph_diffs.set_data(self.x, md.diffs)
        md.line_graph_min_diffs.set_data(self.x, md.min_diffs)
        
        ret.append(md.line_graph_diffs)
        ret.append(md.line_graph_min_diffs)
        ret.append(md.line_graph_threshold)
           
    return ret

m = Moutsouna()

ani = FuncAnimation(plt.gcf(), m.frame_update, init_func=m.frame_init, blit=True, cache_frame_data=True, interval=1, save_count=sys.maxsize)
cid = plt.gcf().canvas.mpl_connect("key_press_event", m.qumbi)

plt.show()

# ani.save('test.mp4')
        
m.video_capture.release()
cv2.destroyAllWindows()  